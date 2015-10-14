/*
 * Copyright (C) 2015 Matias Bjorling <m@bjorling.me>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 * Implementation of a block manager for hybrid open-channel SSD.
 */

#include "bm_hb.h"

static void hb_blocks_free(struct nvm_dev *dev)
{
	struct bm_hb *bm = dev->bmp;
	struct bm_lun *lun;
	int i;

	bm_for_each_lun(bm, lun, i) {
		if (!lun->vlun.blocks)
			break;
		vfree(lun->vlun.blocks);
	}
}

static void hb_luns_free(struct nvm_dev *dev)
{
	struct bm_hb *bm = dev->bmp;

	kfree(bm->luns);
}

static int hb_luns_init(struct nvm_dev *dev, struct bm_hb *bm)
{
	struct bm_lun *lun;
	int i;

	bm->luns = kcalloc(dev->nr_luns, sizeof(struct bm_lun), GFP_KERNEL);
	if (!bm->luns)
		return -ENOMEM;

	bm_for_each_lun(bm, lun, i) {
		spin_lock_init(&lun->vlun.lock);
		INIT_LIST_HEAD(&lun->free_list);
		INIT_LIST_HEAD(&lun->used_list);
		INIT_LIST_HEAD(&lun->bb_list);

		lun->reserved_blocks = 2; /* for GC only */
		lun->vlun.id = i;
		lun->vlun.lun_id = i % dev->luns_per_chnl;
		lun->vlun.chnl_id = i / dev->luns_per_chnl;
		lun->vlun.nr_free_blocks = dev->blks_per_lun;
	}
	return 0;
}

static int hb_block_bb(u32 lun_id, void *bb_bitmap, unsigned int nr_blocks,
								void *private)
{
	struct bm_hb *bm = private;
	struct bm_lun *lun = &bm->luns[lun_id];
	struct nvm_block *block;
	int i;

	if (unlikely(bitmap_empty(bb_bitmap, nr_blocks)))
		return 0;

	i = -1;
	while ((i = find_next_bit(bb_bitmap, nr_blocks, i + 1)) <
			nr_blocks) {
		block = &lun->vlun.blocks[i];
		if (!block) {
			pr_err("bm_hb: BB data is out of bounds!\n");
			return -EINVAL;
		}
		list_move_tail(&block->list, &lun->bb_list);
	}

	return 0;
}

static int hb_block_map(u64 slba, u64 nlb, u64 *entries, void *private)
{
	struct nvm_dev *dev = private;
	struct bm_hb *bm = dev->bmp;
	sector_t max_pages = dev->total_pages * (dev->sec_size >> 9);
	u64 elba = slba + nlb;
	struct bm_lun *lun;
	struct nvm_block *blk;
	u64 i;
	int lun_id;

	if (unlikely(elba > dev->total_pages)) {
		pr_err("bm_hb: L2P data from device is out of bounds!\n");
		return -EINVAL;
	}

	for (i = 0; i < nlb; i++) {
		u64 pba = le64_to_cpu(entries[i]);

		if (unlikely(pba >= max_pages && pba != U64_MAX)) {
			pr_err("bm_hb: L2P data entry is out of bounds!\n");
			return -EINVAL;
		}

		/* Address zero is a special one. The first page on a disk is
		 * protected. As it often holds internal device boot
		 * information. */
		if (!pba)
			continue;

		/* resolve block from physical address */
		lun_id = pba / dev->sec_per_lun;
		lun = &bm->luns[lun_id];

		/* Calculate block offset into lun */
		pba = pba - (dev->sec_per_lun * lun_id);
		blk = &lun->vlun.blocks[pba / dev->sec_per_blk];

		if (!blk->type) {
			/* at this point, we don't know anything about the
			 * block. It's up to the FTL on top to re-etablish the
			 * block state */
			list_move_tail(&blk->list, &lun->used_list);
			blk->type = 1;
			lun->vlun.nr_free_blocks--;
		}
	}

	return 0;
}

static int hb_blocks_init(struct nvm_dev *dev, struct bm_hb *bm)
{
	struct bm_lun *lun;
	struct nvm_block *block;
	sector_t lun_iter, blk_iter, cur_block_id = 0;
	int ret;

	bm_for_each_lun(bm, lun, lun_iter) {
		lun->vlun.blocks = vzalloc(sizeof(struct nvm_block) *
							dev->blks_per_lun);
		if (!lun->vlun.blocks)
			return -ENOMEM;

		for (blk_iter = 0; blk_iter < dev->blks_per_lun; blk_iter++) {
			block = &lun->vlun.blocks[blk_iter];

			INIT_LIST_HEAD(&block->list);

			block->lun = &lun->vlun;
			block->id = cur_block_id++;

			/* First block is reserved for device */
			if (unlikely(lun_iter == 0 && blk_iter == 0))
				continue;

			list_add_tail(&block->list, &lun->free_list);
		}

		if (dev->ops->get_bb_tbl) {
			ret = dev->ops->get_bb_tbl(dev->q, lun->vlun.id,
					dev->blks_per_lun, hb_block_bb, bm);
			if (ret)
				pr_err("bm_hb: could not read BB table\n");
		}
	}

	if (dev->ops->get_l2p_tbl) {
		ret = dev->ops->get_l2p_tbl(dev->q, 0, dev->total_pages,
							hb_block_map, dev);
		if (ret) {
			pr_err("bm_hb: could not read L2P table.\n");
			pr_warn("bm_hb: default block initialization");
		}
	}

	return 0;
}

static int hb_register(struct nvm_dev *dev)
{
	struct bm_hb *bm;
	int ret;

	if (!(dev->features.rsp & NVM_RSP_L2P))
		return 0;

	bm = kzalloc(sizeof(struct bm_hb), GFP_KERNEL);
	if (!bm)
		return -ENOMEM;

	bm->nr_luns = dev->nr_luns;
	dev->bmp = bm;

	ret = hb_luns_init(dev, bm);
	if (ret) {
		pr_err("bm_hb: could not initialize luns\n");
		goto err;
	}

	ret = hb_blocks_init(dev, bm);
	if (ret) {
		pr_err("bm_hb: could not initialize blocks\n");
		goto err;
	}

	return 1;
err:
	kfree(bm);
	return ret;
}

static void hb_unregister(struct nvm_dev *dev)
{
	hb_blocks_free(dev);
	hb_luns_free(dev);
	kfree(dev->bmp);
	dev->bmp = NULL;
}

static struct nvm_block *hb_get_blk(struct nvm_dev *dev, struct nvm_lun *vlun,
							unsigned long flags)
{
	struct bm_lun *lun = container_of(vlun, struct bm_lun, vlun);
	struct nvm_block *blk = NULL;
	int is_gc = flags & NVM_IOTYPE_GC;

	BUG_ON(!lun);

	spin_lock(&vlun->lock);

	if (list_empty(&lun->free_list)) {
		pr_err_ratelimited("bm_hb: lun %u have no free pages available",
								lun->vlun.id);
		spin_unlock(&vlun->lock);
		goto out;
	}

	while (!is_gc && lun->vlun.nr_free_blocks < lun->reserved_blocks) {
		spin_unlock(&vlun->lock);
		goto out;
	}

	blk = list_first_entry(&lun->free_list, struct nvm_block, list);
	list_move_tail(&blk->list, &lun->used_list);
	blk->type = 1;

	lun->vlun.nr_free_blocks--;

	spin_unlock(&vlun->lock);
out:
	return blk;
}

static void hb_put_blk(struct nvm_dev *dev, struct nvm_block *blk)
{
	struct nvm_lun *vlun = blk->lun;
	struct bm_lun *lun = container_of(vlun, struct bm_lun, vlun);

	spin_lock(&vlun->lock);

	switch (blk->type) {
	case 1:
		list_move_tail(&blk->list, &lun->free_list);
		lun->vlun.nr_free_blocks++;
		blk->type = 0;
		break;
	case 2:
		list_move_tail(&blk->list, &lun->bb_list);
		break;
	default:
		BUG();
	}

	spin_unlock(&vlun->lock);
}

static void hb_addr_to_generic_mode(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	int i;

	if (rqd->nr_pages > 1)
		for (i = 0; i < rqd->nr_pages; i++)
			rqd->ppa_list[i] = addr_to_generic_mode(dev,
							rqd->ppa_list[i]);
	else
		rqd->ppa_addr = addr_to_generic_mode(dev, rqd->ppa_addr);
}

static void hb_generic_to_addr_mode(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	int i;

	if (rqd->nr_pages > 1)
		for (i = 0; i < rqd->nr_pages; i++)
			rqd->ppa_list[i] = generic_to_addr_mode(dev,
							rqd->ppa_list[i]);
	else
		rqd->ppa_addr = generic_to_addr_mode(dev, rqd->ppa_addr);
}

static int hb_submit_io(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	if (!dev->ops->submit_io)
		return 0;

	/* Convert address space */
	hb_generic_to_addr_mode(dev, rqd);

	rqd->dev = dev;
	return dev->ops->submit_io(dev->q, rqd);
}

static void hb_blk_set_type(struct nvm_dev *dev, struct ppa_addr *ppa, int type)
{
	struct bm_hb *bm = dev->bmp;
	struct bm_lun *lun;
	struct nvm_block *blk;

	BUG_ON(ppa->g.ch > dev->nr_chnls);
	BUG_ON(ppa->g.lun > dev->luns_per_chnl);
	BUG_ON(ppa->g.blk > dev->blks_per_lun);

	lun = &bm->luns[ppa->g.lun * ppa->g.ch];
	blk = &lun->vlun.blocks[ppa->g.blk];

	/* will be moved to bb list on put_blk from target */
	blk->type = type;
}

/* mark block bad. It is expected the target recover from the error. */
static void hb_mark_blk_bad(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	int i;

	if (!dev->ops->set_bb)
		return;

	if (dev->ops->set_bb(dev->q, rqd, 1))
		return;

	hb_addr_to_generic_mode(dev, rqd);

	/* look up blocks and mark them as bad */
	if (rqd->nr_pages > 1)
		for (i = 0; i < rqd->nr_pages; i++)
			hb_blk_set_type(dev, &rqd->ppa_list[i], 2);
	else
		hb_blk_set_type(dev, &rqd->ppa_addr, 2);
}

static void hb_end_io(struct nvm_rq *rqd, int error)
{
	struct nvm_tgt_instance *ins = rqd->ins;

	if (error == NVM_RSP_ERR_FAILWRITE)
		hb_mark_blk_bad(rqd->dev, rqd);

	ins->tt->end_io(rqd, error);
}

static int hb_erase_blk(struct nvm_dev *dev, struct nvm_block *blk,
							unsigned long flags)
{
	int plane_cnt = 0, pl_idx, ret;
	struct ppa_addr addr;
	struct nvm_rq rqd;

	if (!dev->ops->erase_block)
		return 0;

	addr = block_to_ppa(dev, blk);

	if (dev->plane_mode == NVM_PLANE_SINGLE) {
		rqd.nr_pages = 1;
		rqd.ppa_addr = addr;
	} else {
		plane_cnt = (1 << dev->plane_mode);
		rqd.nr_pages = plane_cnt;

		rqd.ppa_list = nvm_dev_dma_alloc(dev, GFP_KERNEL,
							&rqd.dma_ppa_list);
		if (!rqd.ppa_list) {
			pr_err("bm_hb: failed to allocate dma memory\n");
			return -ENOMEM;
		}

		for (pl_idx = 0; pl_idx < plane_cnt; pl_idx++) {
			addr.g.pl = pl_idx;
			rqd.ppa_list[pl_idx] = addr;
		}
	}

	hb_generic_to_addr_mode(dev, &rqd);

	ret = dev->ops->erase_block(dev->q, &rqd);

	if (plane_cnt)
		nvm_dev_dma_free(dev, rqd.ppa_list, rqd.dma_ppa_list);

	return ret;
}

static struct nvm_lun *hb_get_lun(struct nvm_dev *dev, int lunid)
{
	struct bm_hb *bm = dev->bmp;

	return &bm->luns[lunid].vlun;
}

static void hb_free_blocks_print(struct nvm_dev *dev)
{
	struct bm_hb *bm = dev->bmp;
	struct bm_lun *lun;
	unsigned int i;

	bm_for_each_lun(bm, lun, i)
		pr_info("%s: lun%8u\t%u\n",
					dev->name, i, lun->vlun.nr_free_blocks);
}

static struct nvm_bm_type bm_hb = {
	.name		= "hb",
	.version	= {0, 1, 0},

	.register_bm	= hb_register,
	.unregister_bm	= hb_unregister,

	.get_blk	= hb_get_blk,
	.put_blk	= hb_put_blk,

	.submit_io	= hb_submit_io,
	.end_io		= hb_end_io,
	.erase_blk	= hb_erase_blk,

	.get_lun	= hb_get_lun,
	.free_blocks_print = hb_free_blocks_print,
};

static int __init hb_module_init(void)
{
	return nvm_register_bm(&bm_hb);
}

static void hb_module_exit(void)
{
	nvm_unregister_bm(&bm_hb);
}

module_init(hb_module_init);
module_exit(hb_module_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Block manager for Hybrid Open-Channel SSDs");
