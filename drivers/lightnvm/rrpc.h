/*
 * Copyright (C) 2015 IT University of Copenhagen
 * Initial release: Matias Bjorling <mabj@itu.dk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Implementation of a Round-robin page-based Hybrid FTL for Open-channel SSDs.
 */

#ifndef RRPC_H_
#define RRPC_H_

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/kthread.h>

#include <linux/lightnvm.h>

/* We partition the namespace of translation map into these pieces for tracking
 * in-flight addresses. */
#define NVM_INFLIGHT_PARTITIONS 1

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 10
#define GC_TIME_SECS 100

struct nvm_inflight {
	spinlock_t lock;
	struct list_head reqs;
};

struct rrpc_lun;

struct rrpc_block {
	struct nvm_block *parent;
	struct list_head prio;
};

struct rrpc_lun {
	struct rrpc *rrpc;
	struct nvm_lun *parent;
	struct nvm_block *cur, *gc_cur;
	struct rrpc_block *blocks;	/* Reference to block allocation */
	struct list_head prio_list;		/* Blocks that may be GC'ed */
	struct work_struct ws_gc;

	int nr_blocks;
	spinlock_t lock;
};

struct rrpc {
	/* instance must be kept in top to resolve rrpc in prep/unprep */
	struct nvm_target_instance instance;

	struct nvm_dev *q_nvm;
	struct request_queue *q_dev;
	struct block_device *q_bdev;

	int nr_luns;
	int lun_offset;
	sector_t poffset; /* physical page offset */

	struct rrpc_lun *luns;

	/* calculated values */
	unsigned long nr_pages;
	unsigned long total_blocks;

	/* Write strategy variables. Move these into each for structure for each
	 * strategy */
	atomic_t next_lun; /* Whenever a page is written, this is updated
			    * to point to the next write lun */

	/* Simple translation map of logical addresses to physical addresses.
	 * The logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device. */
	struct nvm_addr *trans_map;
	/* also store a reverse map for garbage collection */
	struct nvm_rev_addr *rev_trans_map;
	spinlock_t rev_lock;

	struct nvm_inflight inflight_map[NVM_INFLIGHT_PARTITIONS];

	mempool_t *addr_pool;
	mempool_t *page_pool;
	mempool_t *gcb_pool;

	struct timer_list gc_timer;
	struct workqueue_struct *krqd_wq;
	struct workqueue_struct *kgc_wq;

	struct gc_blocks *gblks;
	struct gc_luns *gluns;
};

struct rrpc_block_gc {
	struct rrpc *rrpc;
	struct nvm_block *block;
	struct work_struct ws_gc;
};

static inline sector_t nvm_get_laddr(struct request *rq)
{
	return blk_rq_pos(rq) / NR_PHY_IN_LOG;
}

static inline sector_t nvm_get_sector(sector_t laddr)
{
	return laddr * NR_PHY_IN_LOG;
}

static inline int request_intersects(struct rrpc_inflight_rq *r,
				sector_t laddr_start, sector_t laddr_end)
{
	return (laddr_end >= r->l_start && laddr_end <= r->l_end) &&
		(laddr_start >= r->l_start && laddr_start <= r->l_end);
}

static int __rrpc_lock_laddr(struct rrpc *rrpc, sector_t laddr,
			     unsigned pages, struct rrpc_inflight_rq *r)
{
	struct nvm_inflight *map =
			&rrpc->inflight_map[laddr % NVM_INFLIGHT_PARTITIONS];
	sector_t laddr_end = laddr + pages - 1;
	struct rrpc_inflight_rq *rtmp;

	spin_lock_irq(&map->lock);
	list_for_each_entry(rtmp, &map->reqs, list) {
		if (unlikely(request_intersects(rtmp, laddr, laddr_end))) {
			/* existing, overlapping request, come back later */
			spin_unlock_irq(&map->lock);
			return 1;
		}
	}

	r->l_start = laddr;
	r->l_end = laddr_end;

	list_add_tail(&r->list, &map->reqs);
	spin_unlock_irq(&map->lock);
	return 0;
}

static inline int rrpc_lock_laddr(struct rrpc *rrpc, sector_t laddr,
				 unsigned pages,
				 struct rrpc_inflight_rq *r)
{
	BUG_ON((laddr + pages) > rrpc->nr_pages);

	return __rrpc_lock_laddr(rrpc, laddr, pages, r);
}

static inline struct rrpc_inflight_rq *rrpc_get_inflight_rq(struct nvm_rq *n)
{
	return &n->inflight_rq;
}

static inline struct rrpc *get_rrpc_from_rq(struct request *rq)
{
	return rq->sense;
}

static inline int rrpc_lock_rq(struct rrpc *rrpc, struct request *rq,
							struct nvm_rq *rqdata)
{
	sector_t laddr = nvm_get_laddr(rq);
	unsigned int pages = blk_rq_bytes(rq) / EXPOSED_PAGE_SIZE;
	struct rrpc_inflight_rq *r = rrpc_get_inflight_rq(rqdata);

	if (get_rrpc_from_rq(rq))
		return 0;

	return rrpc_lock_laddr(rrpc, laddr, pages, r);
}

static inline void rrpc_unlock_laddr(struct rrpc *rrpc, sector_t laddr,
				    struct rrpc_inflight_rq *r)
{
	struct nvm_inflight *map =
			&rrpc->inflight_map[laddr % NVM_INFLIGHT_PARTITIONS];
	unsigned long flags;

	spin_lock_irqsave(&map->lock, flags);
	list_del_init(&r->list);
	spin_unlock_irqrestore(&map->lock, flags);
}

static inline void rrpc_unlock_rq(struct rrpc *rrpc, struct request *rq,
							struct nvm_rq *rqdata)
{
	sector_t laddr = nvm_get_laddr(rq);
	unsigned int pages = blk_rq_bytes(rq) / EXPOSED_PAGE_SIZE;
	struct rrpc_inflight_rq *r = rrpc_get_inflight_rq(rqdata);

	if (get_rrpc_from_rq(rq))
		return;

	BUG_ON((laddr + pages) > rrpc->nr_pages);

	rrpc_unlock_laddr(rrpc, laddr, r);
}

#endif /* RRPC_H_ */
