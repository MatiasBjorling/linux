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

#include "rrpc.h"

static struct kmem_cache *_gcb_cache;
static DECLARE_RWSEM(_lock);

#define rrpc_for_each_lun(rrpc, rlun, i) \
		for ((i) = 0, rlun = &(rrpc)->luns[0]; \
			(i) < (rrpc)->nr_luns; (i)++, rlun = &(rrpc)->luns[(i)])

static void invalidate_block_page(struct nvm_addr *p)
{
	struct nvm_block *block = p->block;
	unsigned int page_offset;

	if (!block)
		return;

	spin_lock(&block->lock);
	page_offset = p->addr % block->lun->nr_pages_per_blk;
	WARN_ON(test_and_set_bit(page_offset, block->invalid_pages));
	block->nr_invalid_pages++;
	spin_unlock(&block->lock);
}

static inline void __nvm_page_invalidate(struct rrpc *rrpc, struct nvm_addr *a)
{
	BUG_ON(!spin_is_locked(&rrpc->rev_lock));
	if (a->addr == ADDR_EMPTY)
		return;

	invalidate_block_page(a);
	rrpc->rev_trans_map[a->addr - rrpc->poffset].addr = ADDR_EMPTY;
}

static void rrpc_invalidate_range(struct rrpc *rrpc, sector_t slba,
								unsigned len)
{
	sector_t i;

	spin_lock(&rrpc->rev_lock);
	for (i = slba; i < slba + len; i++) {
		struct nvm_addr *gp = &rrpc->trans_map[i];

		__nvm_page_invalidate(rrpc, gp);
		gp->block = NULL;
	}
	spin_unlock(&rrpc->rev_lock);
}

static struct nvm_rq *rrpc_inflight_laddr_acquire(struct rrpc *rrpc,
					sector_t laddr, unsigned int pages)
{
	struct nvm_rq *rqdata;
	struct rrpc_inflight_rq *inf;

	rqdata = kzalloc(sizeof(struct nvm_rq), GFP_ATOMIC);
	if (!rqdata)
		return ERR_PTR(-ENOMEM);

	inf = rrpc_get_inflight_rq(rqdata);
	if (rrpc_lock_laddr(rrpc, laddr, pages, inf)) {
		kfree(rqdata);
		return NULL;
	}

	return rqdata;
}

static void rrpc_inflight_laddr_release(struct rrpc *rrpc, struct nvm_rq *rqdata)
{
	struct rrpc_inflight_rq *inf = rrpc_get_inflight_rq(rqdata);

	rrpc_unlock_laddr(rrpc, inf->l_start, inf);

	kfree(rqdata);
}

static void rrpc_discard(struct rrpc *rrpc, struct bio *bio)
{
	sector_t slba = bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
	sector_t len = bio->bi_iter.bi_size / EXPOSED_PAGE_SIZE;
	struct nvm_rq *rqdata;

	do {
		rqdata = rrpc_inflight_laddr_acquire(rrpc, slba, len);
		schedule();
	} while (!rqdata);

	if (IS_ERR(rqdata)) {
		bio_io_error(bio);
		return;
	}

	rrpc_invalidate_range(rrpc, slba, len);
	rrpc_inflight_laddr_release(rrpc, rqdata);
}

/* requires lun->lock taken */
static void rrpc_set_lun_cur(struct rrpc_lun *rlun, struct nvm_block *block)
{
	BUG_ON(!block);

	if (rlun->cur) {
		spin_lock(&rlun->cur->lock);
		WARN_ON(!block_is_full(rlun->cur));
		spin_unlock(&rlun->cur->lock);
	}
	rlun->cur = block;
}

static struct rrpc_lun *get_next_lun(struct rrpc *rrpc)
{
	int next = atomic_inc_return(&rrpc->next_lun);

	return &rrpc->luns[next % rrpc->nr_luns];
}

static void rrpc_gc_kick(struct rrpc *rrpc)
{
	struct rrpc_lun *rlun;
	unsigned int i;

	for (i = 0; i < rrpc->nr_luns; i++) {
		rlun = &rrpc->luns[i];
		queue_work(rrpc->krqd_wq, &rlun->ws_gc);
	}
}

/**
 * rrpc_gc_timer - default gc timer function.
 * @data: ptr to the 'nvm' structure
 *
 * Description:
 *   rrpc configures a timer to kick the GC to force proactive behavior.
 *
 **/
static void rrpc_gc_timer(unsigned long data)
{
	struct rrpc *rrpc = (struct rrpc *)data;

	rrpc_gc_kick(rrpc);
	mod_timer(&rrpc->gc_timer, jiffies + msecs_to_jiffies(10));
}

/*
 * rrpc_move_valid_pages -- migrate live data off the block
 * @rrpc: the 'rrpc' structure
 * @block: the block from which to migrate live pages
 *
 * Description:
 *   GC algorithms may call this function to migrate remaining live
 *   pages off the block prior to erasing it. This function blocks
 *   further execution until the operation is complete.
 */
static int rrpc_move_valid_pages(struct rrpc *rrpc, struct nvm_block *block)
{
	struct nvm_dev *dev = rrpc->q_nvm;
	struct nvm_lun *lun = block->lun;
	struct nvm_internal_cmd cmd = {
		.target = &rrpc->instance,
		.timeout = 30,
	};
	struct nvm_rev_addr *rev;
	struct nvm_rq *rqdata;
	struct page *page;
	int slot;
	int ret;
	sector_t phys_addr;

	if (bitmap_full(block->invalid_pages, lun->nr_pages_per_blk))
		return 0;

	page = mempool_alloc(rrpc->page_pool, GFP_NOIO);

	while ((slot = find_first_zero_bit(block->invalid_pages,
					   lun->nr_pages_per_blk)) <
						lun->nr_pages_per_blk) {

		/* Lock laddr */
		phys_addr = block_to_addr(block) + slot;

try:
		spin_lock(&rrpc->rev_lock);
		/* Get logical address from physical to logical table */
		rev = &rrpc->rev_trans_map[phys_addr - rrpc->poffset];
		/* already updated by previous regular write */
		if (rev->addr == ADDR_EMPTY) {
			spin_unlock(&rrpc->rev_lock);
			continue;
		}

		rqdata = rrpc_inflight_laddr_acquire(rrpc, rev->addr, 1);
		if (IS_ERR_OR_NULL(rqdata)) {
			spin_unlock(&rrpc->rev_lock);
			schedule();
			goto try;
		}

		spin_unlock(&rrpc->rev_lock);

		cmd.phys_lba = rev->addr;
		cmd.rw = READ;
		cmd.buffer = page_address(page);
		cmd.bufflen = EXPOSED_PAGE_SIZE;
		ret = nvm_internal_rw(dev, &cmd);
		if (ret) {
			pr_err("nvm: gc read failure.\n");
			goto out;
		}

		/* turn the command around and write the data back to a new
		 * address */
		cmd.rw = WRITE;
		ret = nvm_internal_rw(dev, &cmd);
		if (ret) {
			pr_err("nvm: gc write failure.\n");
			goto out;
		}

		rrpc_inflight_laddr_release(rrpc, rqdata);
	}

	mempool_free(page, rrpc->page_pool);

out:
	if (!bitmap_full(block->invalid_pages, lun->nr_pages_per_blk)) {
		pr_err("nvm: failed to garbage collect block\n");
		return -EIO;
	}

	return 0;
}

static void rrpc_block_gc(struct work_struct *work)
{
	struct rrpc_block_gc *gcb = container_of(work, struct rrpc_block_gc,
									ws_gc);
	struct rrpc *rrpc = gcb->rrpc;
	struct nvm_block *block = gcb->block;
	struct nvm_dev *dev = rrpc->q_nvm;

	pr_debug("nvm: block '%d' being reclaimed\n", block->id);

	if (rrpc_move_valid_pages(rrpc, block))
		goto done;

	nvm_erase_blk(dev, block);
	nvm_put_blk(block);
done:
	mempool_free(gcb, rrpc->gcb_pool);
}

/* the block with highest number of invalid pages, will be in the beginning
 * of the list */
static struct rrpc_block *rblock_max_invalid(struct rrpc_block *ra,
					       struct rrpc_block *rb)
{
	struct nvm_block *a = ra->parent;
	struct nvm_block *b = rb->parent;

	BUG_ON(!a || !b);

	if (a->nr_invalid_pages == b->nr_invalid_pages)
		return ra;

	return (a->nr_invalid_pages < b->nr_invalid_pages) ? rb : ra;
}

/* linearly find the block with highest number of invalid pages
 * requires lun->lock */
static struct rrpc_block *block_prio_find_max(struct rrpc_lun *rlun)
{
	struct list_head *prio_list = &rlun->prio_list;
	struct rrpc_block *rblock, *max;

	BUG_ON(list_empty(prio_list));

	max = list_first_entry(prio_list, struct rrpc_block, prio);
	list_for_each_entry(rblock, prio_list, prio)
		max = rblock_max_invalid(max, rblock);

	return max;
}

static void rrpc_lun_gc(struct work_struct *work)
{
	struct rrpc_lun *rlun = container_of(work, struct rrpc_lun, ws_gc);
	struct rrpc *rrpc = rlun->rrpc;
	struct nvm_lun *lun = rlun->parent;
	struct rrpc_block_gc *gcb;
	unsigned int nr_blocks_need;

	nr_blocks_need = lun->nr_blocks / GC_LIMIT_INVERSE;

	if (nr_blocks_need < rrpc->nr_luns)
		nr_blocks_need = rrpc->nr_luns;

	spin_lock(&lun->lock);
	while (nr_blocks_need > lun->nr_free_blocks &&
					!list_empty(&rlun->prio_list)) {
		struct rrpc_block *rblock = block_prio_find_max(rlun);
		struct nvm_block *block = rblock->parent;

		if (!block->nr_invalid_pages)
			break;

		list_del_init(&rblock->prio);

		BUG_ON(!block_is_full(block));

		pr_debug("nvm: selected block '%d' as GC victim\n",
								block->id);

		gcb = mempool_alloc(rrpc->gcb_pool, GFP_ATOMIC);
		if (!gcb)
			break;

		gcb->rrpc = rrpc;
		gcb->block = rblock->parent;
		INIT_WORK(&gcb->ws_gc, rrpc_block_gc);

		queue_work(rrpc->kgc_wq, &gcb->ws_gc);

		nr_blocks_need--;
	}
	spin_unlock(&lun->lock);

	/* TODO: Hint that request queue can be started again */
}

static void rrpc_gc_queue(struct work_struct *work)
{
	struct rrpc_block_gc *gcb = container_of(work, struct rrpc_block_gc,
									ws_gc);
	struct rrpc *rrpc = gcb->rrpc;
	struct nvm_block *block = gcb->block;
	struct nvm_lun *lun = block->lun;
	struct rrpc_lun *rlun = &rrpc->luns[lun->id - rrpc->lun_offset];
	struct rrpc_block *rblock =
			&rlun->blocks[block->id % lun->nr_blocks];

	spin_lock(&rlun->lock);
	list_add_tail(&rblock->prio, &rlun->prio_list);
	spin_unlock(&rlun->lock);

	mempool_free(gcb, rrpc->gcb_pool);
	pr_debug("nvm: block '%d' is full, allow GC (sched)\n", block->id);
}

static int rrpc_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
							unsigned long arg)
{
	return 0;
}

static int rrpc_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void rrpc_release(struct gendisk *disk, fmode_t mode)
{
}

static const struct block_device_operations rrpc_fops = {
	.owner		= THIS_MODULE,
	.ioctl		= rrpc_ioctl,
	.open		= rrpc_open,
	.release	= rrpc_release,
};

static struct rrpc_lun *__rrpc_get_lun_rr(struct rrpc *rrpc, int is_gc)
{
	unsigned int i;
	struct rrpc_lun *rlun, *max_free;

	if (!is_gc)
		return get_next_lun(rrpc);

	/* FIXME */
	/* during GC, we don't care about RR, instead we want to make
	 * sure that we maintain evenness between the block luns. */
	max_free = &rrpc->luns[0];
	/* prevent GC-ing lun from devouring pages of a lun with
	 * little free blocks. We don't take the lock as we only need an
	 * estimate. */
	rrpc_for_each_lun(rrpc, rlun, i) {
		if (rlun->parent->nr_free_blocks >
					max_free->parent->nr_free_blocks)
			max_free = rlun;
	}

	return max_free;
}

static inline void __rrpc_page_invalidate(struct rrpc *rrpc,
							struct nvm_addr *gp)
{
	BUG_ON(!spin_is_locked(&rrpc->rev_lock));
	if (gp->addr == ADDR_EMPTY)
		return;

	invalidate_block_page(gp);
	rrpc->rev_trans_map[gp->addr - rrpc->poffset].addr = ADDR_EMPTY;
}

struct nvm_addr *nvm_update_map(struct rrpc *rrpc, sector_t l_addr,
			struct nvm_block *p_block, sector_t p_addr, int is_gc)
{
	struct nvm_addr *gp;
	struct nvm_rev_addr *rev;

	BUG_ON(l_addr >= rrpc->nr_pages);

	gp = &rrpc->trans_map[l_addr];
	spin_lock(&rrpc->rev_lock);
	if (gp->block)
		__nvm_page_invalidate(rrpc, gp);

	gp->addr = p_addr;
	gp->block = p_block;

	rev = &rrpc->rev_trans_map[gp->addr - rrpc->poffset];
	rev->addr = l_addr;
	spin_unlock(&rrpc->rev_lock);

	return gp;
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for
 * the next write to the disk.
 *
 * Returns nvm_addr with the physical address and block. Remember to return to
 * rrpc->addr_cache when request is finished.
 */
static struct nvm_addr *rrpc_map_page(struct rrpc *rrpc, sector_t laddr,
								int is_gc)
{
	struct rrpc_lun *rlun;
	struct nvm_lun *lun;
	struct nvm_block *p_block;
	sector_t p_addr;

	rlun = __rrpc_get_lun_rr(rrpc, is_gc);
	lun = rlun->parent;

	if (!is_gc && lun->nr_free_blocks < rrpc->nr_luns * 4)
		return NULL;

	spin_lock(&rlun->lock);

	p_block = rlun->cur;
	p_addr = nvm_alloc_addr(p_block);

	if (p_addr == ADDR_EMPTY) {
		p_block = nvm_get_blk(lun, 0);

		if (!p_block) {
			if (is_gc) {
				p_addr = nvm_alloc_addr(rlun->gc_cur);
				if (p_addr == ADDR_EMPTY) {
					p_block = nvm_get_blk(lun, 1);
					if (!p_block) {
						pr_err("rrpc: no more blocks");
						goto finished;
					} else {
						rlun->gc_cur = p_block;
						p_addr =
						  nvm_alloc_addr(rlun->gc_cur);
					}
				}
				p_block = rlun->gc_cur;
			}
			goto finished;
		}

		rrpc_set_lun_cur(rlun, p_block);
		p_addr = nvm_alloc_addr(p_block);
	}

finished:
	if (p_addr == ADDR_EMPTY)
		goto err;

	if (!p_block)
		WARN_ON(is_gc);

	spin_unlock(&rlun->lock);
	return nvm_update_map(rrpc, laddr, p_block, p_addr, is_gc);
err:
	spin_unlock(&rlun->lock);
	return NULL;
}

static void rrpc_unprep_rq(struct request *rq, struct nvm_rq *rqdata,
								void *private)
{
	struct rrpc *rrpc = private;
	struct nvm_addr *p = rqdata->addr;
	struct nvm_block *block = p->block;
	struct nvm_lun *lun = block->lun;
	struct rrpc_block_gc *gcb;
	int cmnt_size;

	rrpc_unlock_rq(rrpc, rq, rqdata);

	if (rq_data_dir(rq) == WRITE) {
		cmnt_size = atomic_inc_return(&block->data_cmnt_size);
		if (likely(cmnt_size != lun->nr_pages_per_blk))
			return;

		gcb = mempool_alloc(rrpc->gcb_pool, GFP_ATOMIC);
		if (!gcb) {
			pr_err("rrpc: not able to queue block for gc.");
			return;
		}

		gcb->rrpc = rrpc;
		gcb->block = block;
		INIT_WORK(&gcb->ws_gc, rrpc_gc_queue);

		queue_work(rrpc->kgc_wq, &gcb->ws_gc);
	}
}

static int rrpc_read_rq(struct rrpc *rrpc, struct request *rq,
						struct nvm_rq *rqdata)
{
	struct nvm_addr *gp;
	sector_t l_addr = nvm_get_laddr(rq);

	if (rrpc_lock_rq(rrpc, rq, rqdata))
		return NVM_PREP_REQUEUE;

	BUG_ON(!(l_addr >= 0 && l_addr < rrpc->nr_pages));
	gp = &rrpc->trans_map[l_addr];

	if (gp->block) {
		rqdata->phys_sector = nvm_get_sector(gp->addr);
	} else {
		rrpc_unlock_rq(rrpc, rq, rqdata);
		blk_mq_end_request(rq, 0);
		return NVM_PREP_DONE;
	}

	rqdata->addr = gp;

	return NVM_PREP_OK;
}

static int rrpc_write_rq(struct rrpc *rrpc, struct request *rq,
						struct nvm_rq *rqdata)
{
	struct nvm_addr *p;
	int is_gc = 0;
	sector_t l_addr = nvm_get_laddr(rq);

	if (rq->special)
		is_gc = 1;

	if (rrpc_lock_rq(rrpc, rq, rqdata))
		return NVM_PREP_REQUEUE;

	p = rrpc_map_page(rrpc, l_addr, is_gc);
	if (!p) {
		BUG_ON(is_gc);
		rrpc_unlock_rq(rrpc, rq, rqdata);
		rrpc_gc_kick(rrpc);
		return NVM_PREP_REQUEUE;
	}

	rqdata->phys_sector = nvm_get_sector(p->addr);
	rqdata->addr = p;

	return NVM_PREP_OK;
}

static int rrpc_prep_rq(struct request *rq, struct nvm_rq *rqdata,
								void *private)
{
	struct rrpc *rrpc = private;

	if (rq_data_dir(rq) == WRITE)
		return rrpc_write_rq(rrpc, rq, rqdata);

	return rrpc_read_rq(rrpc, rq, rqdata);
}

static void rrpc_make_rq(struct request_queue *q, struct bio *bio)
{
	struct rrpc *rrpc = q->queuedata;

	if (bio->bi_rw & REQ_DISCARD) {
		rrpc_discard(rrpc, bio);
		return;
	}

	bio->bi_nvm = &rrpc->instance.payload;
	bio->bi_bdev = rrpc->q_bdev;

	generic_make_request(bio);
}

static void rrpc_gc_free(struct rrpc *rrpc)
{
	struct rrpc_lun *rlun;
	int i;

	if (rrpc->krqd_wq)
		destroy_workqueue(rrpc->krqd_wq);

	if (rrpc->kgc_wq)
		destroy_workqueue(rrpc->kgc_wq);

	if (!rrpc->luns)
		return;

	for (i = 0; i < rrpc->nr_luns; i++) {
		rlun = &rrpc->luns[i];

		if (!rlun->blocks)
			break;
		vfree(rlun->blocks);
	}
}

static int rrpc_gc_init(struct rrpc *rrpc)
{
	rrpc->krqd_wq = alloc_workqueue("knvm-work", WQ_MEM_RECLAIM|WQ_UNBOUND,
						rrpc->nr_luns);
	if (!rrpc->krqd_wq)
		return -ENOMEM;

	rrpc->kgc_wq = alloc_workqueue("knvm-gc", WQ_MEM_RECLAIM, 1);
	if (!rrpc->kgc_wq)
		return -ENOMEM;

	setup_timer(&rrpc->gc_timer, rrpc_gc_timer, (unsigned long)rrpc);

	return 0;
}

static void rrpc_map_free(struct rrpc *rrpc)
{
	vfree(rrpc->rev_trans_map);
	vfree(rrpc->trans_map);
}

static int rrpc_l2p_update(u64 slba, u64 nlb, u64 *entries, void *private)
{
	struct rrpc *rrpc = (struct rrpc *)private;
	struct nvm_dev *dev = rrpc->q_nvm;
	struct nvm_addr *addr = rrpc->trans_map + slba;
	struct nvm_rev_addr *raddr = rrpc->rev_trans_map;
	sector_t max_pages = dev->total_pages * (dev->sector_size >> 9);
	u64 elba = slba + nlb;
	u64 i;

	if (unlikely(elba > dev->total_pages)) {
		pr_err("nvm: L2P data from device is out of bounds!\n");
		return -EINVAL;
	}

	for (i = 0; i < nlb; i++) {
		u64 pba = le64_to_cpu(entries[i]);
		/* LNVM treats address-spaces as silos, LBA and PBA are
		 * equally large and zero-indexed. */
		if (unlikely(pba >= max_pages && pba != U64_MAX)) {
			pr_err("nvm: L2P data entry is out of bounds!\n");
			return -EINVAL;
		}

		/* Address zero is a special one. The first page on a disk is
		 * protected. As it often holds internal device boot
		 * information. */
		if (!pba)
			continue;

		addr[i].addr = pba;
		raddr[pba].addr = slba + i;
	}

	return 0;
}

static int rrpc_map_init(struct rrpc *rrpc)
{
	struct nvm_dev *dev = rrpc->q_nvm;
	sector_t i;
	int ret;

	rrpc->trans_map = vzalloc(sizeof(struct nvm_addr) * rrpc->nr_pages);
	if (!rrpc->trans_map)
		return -ENOMEM;

	rrpc->rev_trans_map = vmalloc(sizeof(struct nvm_rev_addr)
							* rrpc->nr_pages);
	if (!rrpc->rev_trans_map)
		return -ENOMEM;

	for (i = 0; i < rrpc->nr_pages; i++) {
		struct nvm_addr *p = &rrpc->trans_map[i];
		struct nvm_rev_addr *r = &rrpc->rev_trans_map[i];

		p->addr = ADDR_EMPTY;
		r->addr = ADDR_EMPTY;
	}

	if (!dev->ops->get_l2p_tbl)
		return 0;

	/* Bring up the mapping table from device */
	ret = dev->ops->get_l2p_tbl(dev->q, 0, dev->total_pages,
							rrpc_l2p_update, rrpc);
	if (ret) {
		pr_err("nvm: rrpc: could not read L2P table.\n");
		return -EINVAL;
	}

	return 0;
}


/* Minimum pages needed within a lun */
#define PAGE_POOL_SIZE 16
#define ADDR_POOL_SIZE 64

static int rrpc_core_init(struct rrpc *rrpc)
{
	int i;

	down_write(&_lock);
	if (!_gcb_cache) {
		_gcb_cache = kmem_cache_create("nvm_gcb_cache",
				sizeof(struct rrpc_block_gc), 0, 0, NULL);
		if (!_gcb_cache) {
			up_write(&_lock);
			return -ENOMEM;
		}
	}
	up_write(&_lock);

	rrpc->page_pool = mempool_create_page_pool(PAGE_POOL_SIZE, 0);
	if (!rrpc->page_pool)
		return -ENOMEM;

	rrpc->gcb_pool = mempool_create_slab_pool(rrpc->q_nvm->nr_luns,
								_gcb_cache);
	if (!rrpc->gcb_pool)
		return -ENOMEM;

	for (i = 0; i < NVM_INFLIGHT_PARTITIONS; i++) {
		struct nvm_inflight *map = &rrpc->inflight_map[i];

		spin_lock_init(&map->lock);
		INIT_LIST_HEAD(&map->reqs);
	}

	return 0;
}

static void rrpc_core_free(struct rrpc *rrpc)
{
	if (rrpc->page_pool)
		mempool_destroy(rrpc->page_pool);
	if (rrpc->gcb_pool)
		mempool_destroy(rrpc->gcb_pool);
}

static void rrpc_luns_free(struct rrpc *rrpc)
{
	kfree(rrpc->luns);
}

static int rrpc_luns_init(struct rrpc *rrpc, int lun_begin, int lun_end)
{
	struct nvm_dev *dev = rrpc->q_nvm;
	struct nvm_block *block;
	struct rrpc_lun *rlun;
	int i, j;

	spin_lock_init(&rrpc->rev_lock);

	rrpc->luns = kcalloc(rrpc->nr_luns, sizeof(struct rrpc_lun),
								GFP_KERNEL);
	if (!rrpc->luns)
		return -ENOMEM;

	/* 1:1 mapping */
	for (i = 0; i < rrpc->nr_luns; i++) {
		struct nvm_lun *lun = &dev->luns[i + lun_begin];

		rlun = &rrpc->luns[i];
		rlun->rrpc = rrpc;
		rlun->parent = lun;
		rlun->nr_blocks = lun->nr_blocks;

		rrpc->total_blocks += lun->nr_blocks;
		rrpc->nr_pages += lun->nr_blocks * lun->nr_pages_per_blk;

		INIT_LIST_HEAD(&rlun->prio_list);
		INIT_WORK(&rlun->ws_gc, rrpc_lun_gc);
		spin_lock_init(&rlun->lock);

		rlun->blocks = vzalloc(sizeof(struct rrpc_block) *
						 rlun->nr_blocks);
		if (!rlun->blocks)
			goto err;

		lun_for_each_block(lun, block, j) {
			struct rrpc_block *rblock = &rlun->blocks[j];

			rblock->parent = block;
			INIT_LIST_HEAD(&rblock->prio);
		}
	}

	return 0;
err:
	return -ENOMEM;
}

static void rrpc_free(struct rrpc *rrpc)
{
	rrpc_gc_free(rrpc);
	rrpc_map_free(rrpc);
	rrpc_core_free(rrpc);
	rrpc_luns_free(rrpc);

	kfree(rrpc);
}

static void rrpc_exit(void *private)
{
	struct rrpc *rrpc = private;

	blkdev_put(rrpc->q_bdev, FMODE_WRITE | FMODE_READ);
	del_timer(&rrpc->gc_timer);

	flush_workqueue(rrpc->krqd_wq);
	flush_workqueue(rrpc->kgc_wq);

	rrpc_free(rrpc);
}

static sector_t rrpc_capacity(void *private)
{
	struct rrpc *rrpc = private;
	struct nvm_lun *lun;
	sector_t reserved;
	int i, max_pages_per_blk = 0;

	nvm_for_each_lun(rrpc->q_nvm, lun, i) {
		if (lun->nr_pages_per_blk > max_pages_per_blk)
			max_pages_per_blk = lun->nr_pages_per_blk;
	}

	/* cur, gc, and two emergency blocks for each lun */
	reserved = rrpc->nr_luns * max_pages_per_blk * 4;

	if (reserved > rrpc->nr_pages) {
		pr_err("rrpc: not enough space available to expose storage.\n");
		return 0;
	}

	return ((rrpc->nr_pages - reserved) / 10) * 9 * NR_PHY_IN_LOG;
}

/*
 * Looks up the logical address from reverse trans map and check if its valid by
 * comparing the logical to physical address with the physical address.
 * Returns 0 on free, otherwise 1 if in use
 */
static void rrpc_block_map_update(struct rrpc *rrpc, struct nvm_block *block)
{
	struct nvm_lun *lun = block->lun;
	int offset;
	struct nvm_addr *laddr;
	sector_t paddr, pladdr;

	for (offset = 0; offset < lun->nr_pages_per_blk; offset++) {
		paddr = block_to_addr(block) + offset;

		pladdr = rrpc->rev_trans_map[paddr].addr;
		if (pladdr == ADDR_EMPTY)
			continue;

		laddr = &rrpc->trans_map[pladdr];

		if (paddr == laddr->addr) {
			laddr->block = block;
		} else {
			set_bit(offset, block->invalid_pages);
			block->nr_invalid_pages++;
		}
	}
}

static int rrpc_blocks_init(struct rrpc *rrpc)
{
	struct nvm_dev *dev = rrpc->q_nvm;
	struct nvm_lun *lun;
	struct nvm_block *blk;
	sector_t lun_iter, blk_iter;

	for (lun_iter = 0; lun_iter < rrpc->nr_luns; lun_iter++) {
		lun = &dev->luns[lun_iter + rrpc->lun_offset];

		lun_for_each_block(lun, blk, blk_iter)
			rrpc_block_map_update(rrpc, blk);
	}

	return 0;
}

static int rrpc_luns_configure(struct rrpc *rrpc)
{
	struct rrpc_lun *rlun;
	struct nvm_block *blk;
	int i;

	for (i = 0; i < rrpc->nr_luns; i++) {
		rlun = &rrpc->luns[i];

		blk = nvm_get_blk(rlun->parent, 0);
		if (!blk)
			return -EINVAL;

		rrpc_set_lun_cur(rlun, blk);

		/* Emergency gc block */
		blk = nvm_get_blk(rlun->parent, 1);
		if (!blk)
			return -EINVAL;
		rlun->gc_cur = blk;
	}

	return 0;
}

static struct nvm_target_type tt_rrpc;

static void *rrpc_init(struct gendisk *bdisk, struct gendisk *tdisk,
						int lun_begin, int lun_end)
{
	struct request_queue *bqueue = bdisk->queue;
	struct request_queue *tqueue = tdisk->queue;
	struct nvm_dev *dev;
	struct block_device *bdev;
	struct rrpc *rrpc;
	int ret;

	if (!nvm_get_dev(bdisk)) {
		pr_err("nvm: block device not supported.\n");
		return ERR_PTR(-EINVAL);
	}

	bdev = bdget_disk(bdisk, 0);
	if (blkdev_get(bdev, FMODE_WRITE | FMODE_READ, NULL)) {
		pr_err("nvm: could not access backing device\n");
		return ERR_PTR(-EINVAL);
	}

	dev = nvm_get_dev(bdisk);

	rrpc = kzalloc(sizeof(struct rrpc), GFP_KERNEL);
	if (!rrpc) {
		ret = -ENOMEM;
		goto err;
	}

	rrpc->q_dev = bqueue;
	rrpc->q_nvm = bdisk->nvm;
	rrpc->q_bdev = bdev;
	rrpc->nr_luns = lun_end - lun_begin + 1;
	rrpc->instance.tt = &tt_rrpc;

	/* simple round-robin strategy */
	atomic_set(&rrpc->next_lun, -1);

	ret = rrpc_luns_init(rrpc, lun_begin, lun_end);
	if (ret) {
		pr_err("nvm: could not initialize luns\n");
		goto err;
	}

	rrpc->poffset = rrpc->luns[0].parent->nr_blocks *
			rrpc->luns[0].parent->nr_pages_per_blk * lun_begin;
	rrpc->lun_offset = lun_begin;

	ret = rrpc_core_init(rrpc);
	if (ret) {
		pr_err("nvm: rrpc: could not initialize core\n");
		goto err;
	}

	ret = rrpc_map_init(rrpc);
	if (ret) {
		pr_err("nvm: rrpc: could not initialize maps\n");
		goto err;
	}

	ret = rrpc_blocks_init(rrpc);
	if (ret) {
		pr_err("nvm: rrpc: could not initialize state for blocks\n");
		goto err;
	}

	ret = rrpc_luns_configure(rrpc);
	if (ret) {
		pr_err("nvm: rrpc: not enough blocks available in LUNs.\n");
		goto err;
	}

	ret = rrpc_gc_init(rrpc);
	if (ret) {
		pr_err("nvm: rrpc: could not initialize gc\n");
		goto err;
	}

	/* make sure to inherit the size from the underlying device */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));

	pr_info("nvm: rrpc initialized with %u luns and %llu pages.\n",
			rrpc->nr_luns, (unsigned long long)rrpc->nr_pages);

	mod_timer(&rrpc->gc_timer, jiffies + msecs_to_jiffies(10));

	return rrpc;
err:
	blkdev_put(bdev, FMODE_WRITE | FMODE_READ);
	rrpc_free(rrpc);
	return ERR_PTR(ret);
}

/* round robin, page-based FTL, and cost-based GC */
static struct nvm_target_type tt_rrpc = {
	.name		= "rrpc",

	.make_rq	= rrpc_make_rq,
	.prep_rq	= rrpc_prep_rq,
	.unprep_rq	= rrpc_unprep_rq,

	.capacity	= rrpc_capacity,

	.init		= rrpc_init,
	.exit		= rrpc_exit,
};

static int __init rrpc_module_init(void)
{
	return nvm_register_target(&tt_rrpc);
}

static void rrpc_module_exit(void)
{
	nvm_unregister_target(&tt_rrpc);
}

module_init(rrpc_module_init);
module_exit(rrpc_module_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Round-Robin Cost-based Hybrid Layer for Open-Channel SSDs");
