/*
 * nvme-lightnvm.c - LightNVM NVMe device
 *
 * Copyright (C) 2014-2015 IT University of Copenhagen
 * Initial release: Matias Bjorling <mb@lightnvm.io>
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
 */

#include <linux/nvme.h>
#include <linux/bitops.h>
#include <linux/lightnvm.h>

#ifdef CONFIG_NVM

enum nvme_nvm_opcode {
	nvme_nvm_cmd_hb_write	= 0x81,
	nvme_nvm_cmd_hb_read	= 0x02,
	nvme_nvm_cmd_ph_write	= 0x91,
	nvme_nvm_cmd_ph_read	= 0x92,
	nvme_nvm_cmd_erase	= 0x90,
};

enum nvme_nvm_admin_opcode {
	nvme_nvm_admin_identify		= 0xe2,
	nvme_nvm_admin_get_features	= 0xe6,
	nvme_nvm_admin_set_resp		= 0xe5,
	nvme_nvm_admin_get_l2p_tbl	= 0xea,
	nvme_nvm_admin_get_bb_tbl	= 0xf2,
	nvme_nvm_admin_set_bb_tbl	= 0xf1,
};

struct nvme_nvm_hb_rw {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd2;
	__le64			metadata;
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			length;
	__le16			control;
	__le32			dsmgmt;
	__le64			slba;
};

struct nvme_nvm_ph_rw {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd2;
	__le64			metadata;
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			length;
	__le16			control;
	__le32			dsmgmt;
	__le64			resv;
};

struct nvme_nvm_identify {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le32			chnl_off;
	__u32			rsvd11[5];
};

struct nvme_nvm_l2ptbl {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__le32			cdw2[4];
	__le64			prp1;
	__le64			prp2;
	__le64			slba;
	__le32			nlb;
	__le16			cdw14[6];
};

struct nvme_nvm_bbtbl {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le32			prp1_len;
	__le32			prp2_len;
	__le32			lbb;
	__u32			rsvd11[3];
};

struct nvme_nvm_set_resp {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			resp;
	__u32			rsvd11[4];
};

struct nvme_nvm_erase_blk {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			blk_addr;
	__u32			rsvd11[4];
};

struct nvme_nvm_command {
	union {
		struct nvme_common_command common;
		struct nvme_nvm_identify identify;
		struct nvme_nvm_hb_rw hb_rw;
		struct nvme_nvm_ph_rw ph_rw;
		struct nvme_nvm_l2ptbl l2p;
		struct nvme_nvm_bbtbl get_bb;
		struct nvme_nvm_bbtbl set_bb;
		struct nvme_nvm_set_resp resp;
		struct nvme_nvm_erase_blk erase;
	};
};

/*
 * Check we didin't inadvertently grow the command struct
 */
static inline void _nvme_nvm_check_size(void)
{
	BUILD_BUG_ON(sizeof(struct nvme_nvm_identify) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_hb_rw) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_ph_rw) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_l2ptbl) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_bbtbl) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_set_resp) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_erase_blk) != 64);
}

struct nvme_nvm_id_chnl {
	__le64			laddr_begin;
	__le64			laddr_end;
	__le32			oob_size;
	__le32			queue_size;
	__le32			gran_read;
	__le32			gran_write;
	__le32			gran_erase;
	__le32			t_r;
	__le32			t_sqr;
	__le32			t_w;
	__le32			t_sqw;
	__le32			t_e;
	__le16			chnl_parallelism;
	__u8			io_sched;
	__u8			reserved[133];
} __packed;

struct nvme_nvm_id {
	__u8			ver_id;
	__u8			nvm_type;
	__le16			nchannels;
	__u8			reserved[252];
	struct nvme_nvm_id_chnl	chnls[];
} __packed;

#define NVME_NVM_CHNLS_PR_REQ ((4096U - sizeof(struct nvme_nvm_id)) \
					/ sizeof(struct nvme_nvm_id_chnl))


static int init_chnls(struct request_queue *q, struct nvm_id *nvm_id,
						struct nvme_nvm_id *nvme_nvm_id)
{
	struct nvme_nvm_id_chnl *src = nvme_nvm_id->chnls;
	struct nvm_id_chnl *dst = nvm_id->chnls;
	struct nvme_ns *ns = q->queuedata;
	struct nvme_nvm_command c = {};
	unsigned int len = nvm_id->nchannels;
	int i, end, ret, off = 0;

	c.identify.opcode = nvme_nvm_admin_identify;
	c.identify.nsid = cpu_to_le32(ns->ns_id);

	while (len) {
		end = min_t(u32, NVME_NVM_CHNLS_PR_REQ, len);

		for (i = 0; i < end; i++, dst++, src++) {
			dst->laddr_begin = le64_to_cpu(src->laddr_begin);
			dst->laddr_end = le64_to_cpu(src->laddr_end);
			dst->oob_size = le32_to_cpu(src->oob_size);
			dst->queue_size = le32_to_cpu(src->queue_size);
			dst->gran_read = le32_to_cpu(src->gran_read);
			dst->gran_write = le32_to_cpu(src->gran_write);
			dst->gran_erase = le32_to_cpu(src->gran_erase);
			dst->t_r = le32_to_cpu(src->t_r);
			dst->t_sqr = le32_to_cpu(src->t_sqr);
			dst->t_w = le32_to_cpu(src->t_w);
			dst->t_sqw = le32_to_cpu(src->t_sqw);
			dst->t_e = le32_to_cpu(src->t_e);
			dst->io_sched = src->io_sched;
		}

		len -= end;
		if (!len)
			break;

		off += end;

		c.identify.chnl_off = off;

		ret = nvme_submit_sync_cmd(q, (struct nvme_command *)&c,
							nvme_nvm_id, 4096);
		if (ret)
			return ret;
	}
	return 0;
}

static int nvme_nvm_identify(struct request_queue *q, struct nvm_id *nvm_id)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_nvm_id *nvme_nvm_id;
	struct nvme_nvm_command c = {};
	int ret;

	c.identify.opcode = nvme_nvm_admin_identify;
	c.identify.nsid = cpu_to_le32(ns->ns_id);
	c.identify.chnl_off = 0;
	nvme_nvm_id = kmalloc(4096, GFP_KERNEL);
	if (!nvme_nvm_id)
		return -ENOMEM;

	ret = nvme_submit_sync_cmd(q, (struct nvme_command *)&c, nvme_nvm_id,
									4096);
	if (ret) {
		ret = -EIO;
		goto out;
	}

	nvm_id->ver_id = nvme_nvm_id->ver_id;
	nvm_id->nvm_type = nvme_nvm_id->nvm_type;
	nvm_id->nchannels = le16_to_cpu(nvme_nvm_id->nchannels);

	if (!nvm_id->chnls)
		nvm_id->chnls = kmalloc(sizeof(struct nvm_id_chnl)
					* nvm_id->nchannels, GFP_KERNEL);
	if (!nvm_id->chnls) {
		ret = -ENOMEM;
		goto out;
	}

	ret = init_chnls(q, nvm_id, nvme_nvm_id);
out:
	kfree(nvme_nvm_id);
	return ret;
}

static int nvme_nvm_get_features(struct request_queue *q,
						struct nvm_get_features *gf)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_nvm_command c = {};
	int sz = sizeof(struct nvm_get_features);
	int ret;
	u64 *resp;

	c.common.opcode = nvme_nvm_admin_get_features;
	c.common.nsid = ns->ns_id;
	resp = kmalloc(sz, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	ret = nvme_submit_sync_cmd(q, (struct nvme_command *)&c, resp, sz);
	if (ret)
		goto done;

	gf->rsp = le64_to_cpu(resp[0]);
	gf->ext = le64_to_cpu(resp[1]);

done:
	kfree(resp);
	return ret;
}

static int nvme_nvm_set_resp(struct request_queue *q, u64 resp)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_nvm_command c = {};

	c.resp.opcode = nvme_nvm_admin_set_resp;
	c.resp.nsid = cpu_to_le32(ns->ns_id);
	c.resp.resp = cpu_to_le64(resp);
	return nvme_submit_sync_cmd(q, (struct nvme_command *)&c, NULL, 0);
}

static int nvme_nvm_get_l2p_tbl(struct request_queue *q, u64 slba, u64 nlb,
				nvm_l2p_update_fn *update_l2p, void *priv)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *dev = ns->dev;
	struct nvme_nvm_command c = {};
	u32 len = queue_max_hw_sectors(q) << 9;
	u64 nlb_pr_rq = len / sizeof(u64);
	u64 cmd_slba = slba;
	void *entries;
	int ret = 0;

	c.l2p.opcode = nvme_nvm_admin_get_l2p_tbl;
	c.l2p.nsid = cpu_to_le32(ns->ns_id);
	entries = kmalloc(len, GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	while (nlb) {
		u64 cmd_nlb = min_t(u64, nlb_pr_rq, nlb);

		c.l2p.slba = cmd_slba;
		c.l2p.nlb = cmd_nlb;

		ret = nvme_submit_sync_cmd(q, (struct nvme_command *)&c,
								entries, len);
		if (ret) {
			dev_err(dev->dev, "L2P table transfer failed (%d)\n",
									ret);
			ret = -EIO;
			goto out;
		}

		if (update_l2p(cmd_slba, cmd_nlb, entries, priv)) {
			ret = -EINTR;
			goto out;
		}

		cmd_slba += cmd_nlb;
		nlb -= cmd_nlb;
	}

out:
	kfree(entries);
	return ret;
}

static int nvme_nvm_set_bb_tbl(struct request_queue *q, int lunid,
	unsigned int nr_blocks, nvm_bb_update_fn *update_bbtbl, void *priv)
{
	return 0;
}

static int nvme_nvm_get_bb_tbl(struct request_queue *q, int lunid,
	unsigned int nr_blocks, nvm_bb_update_fn *update_bbtbl, void *priv)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *dev = ns->dev;
	struct nvme_nvm_command c = {};
	void *bb_bitmap;
	u16 bb_bitmap_size;
	int ret = 0;

	c.get_bb.opcode = nvme_nvm_admin_get_bb_tbl;
	c.get_bb.nsid = cpu_to_le32(ns->ns_id);
	c.get_bb.lbb = cpu_to_le32(lunid);
	bb_bitmap_size = ((nr_blocks >> 15) + 1) * PAGE_SIZE;
	bb_bitmap = kmalloc(bb_bitmap_size, GFP_KERNEL);
	if (!bb_bitmap)
		return -ENOMEM;

	bitmap_zero(bb_bitmap, nr_blocks);

	ret = nvme_submit_sync_cmd(q, (struct nvme_command *)&c, bb_bitmap,
								bb_bitmap_size);
	if (ret) {
		dev_err(dev->dev, "get bad block table failed (%d)\n", ret);
		ret = -EIO;
		goto out;
	}

	ret = update_bbtbl(lunid, bb_bitmap, nr_blocks, priv);
	if (ret) {
		ret = -EINTR;
		goto out;
	}

out:
	kfree(bb_bitmap);
	return ret;
}

static inline void nvme_nvm_cmd_hybrid(struct nvm_rq *rqd, struct nvme_ns *ns,
						struct nvme_nvm_command *c)
{
	c->hb_rw.opcode = (rqd->opcode & 1) ?
				nvme_nvm_cmd_hb_write : nvme_nvm_cmd_hb_read;
	c->hb_rw.nsid = cpu_to_le32(ns->ns_id);
	if (rqd->npages == 1)
		c->hb_rw.spba = cpu_to_le64(nvme_block_nr(ns, rqd->ppa));
	else
		c->hb_rw.spba = cpu_to_le64(rqd->dma_ppa_list);
	c->hb_rw.length = cpu_to_le16(rqd->npages - 1);
	c->hb_rw.slba = cpu_to_le64(nvme_block_nr(ns,
						rqd->bio->bi_iter.bi_sector));
}

static inline void nvme_nvm_cmd_phys(struct nvm_rq *rqd, struct nvme_ns *ns,
						struct nvme_nvm_command *c)
{
	c->ph_rw.opcode = (rqd->opcode & 1) ?
				nvme_nvm_cmd_ph_write : nvme_nvm_cmd_ph_read;
	c->ph_rw.nsid = cpu_to_le32(ns->ns_id);
	if (rqd->npages == 1)
		c->ph_rw.spba = cpu_to_le64(nvme_block_nr(ns, rqd->ppa));
	else
		c->ph_rw.spba = cpu_to_le64(rqd->dma_ppa_list);
	c->ph_rw.length = cpu_to_le16(rqd->npages - 1);
}

static inline void nvme_nvm_rqtocmd(struct request *rq, struct nvm_rq *rqd,
				struct nvme_ns *ns, struct nvme_nvm_command *c)
{
	switch (rqd->opcode) {
	case NVM_OP_HBWRITE:
	case NVM_OP_HBREAD:
		nvme_nvm_cmd_hybrid(rqd, ns, c);
		break;
	case NVM_OP_PWRITE:
	case NVM_OP_PREAD:
		nvme_nvm_cmd_phys(rqd, ns, c);
		break;
	default:
		pr_err("nvm: invalid opcode\n");
	}
}

static void nvme_nvm_end_io(struct request *rq, int error)
{
	struct nvm_rq *rqd = rq->end_io_data;
	struct nvm_tgt_instance *ins = rqd->ins;

	ins->tt->end_io(rqd, error);

	kfree(rq->cmd);
	blk_mq_free_request(rq);
}

static int nvme_nvm_submit_io(struct request_queue *q, struct nvm_rq *rqd)
{
	struct nvme_ns *ns = q->queuedata;
	struct request *rq;
	struct bio *bio = rqd->bio;
	struct nvme_nvm_command *cmd;

	rq = blk_mq_alloc_request(q, bio_rw(bio), GFP_KERNEL, 0);
	if (IS_ERR(rq))
		return -ENOMEM;

	cmd = kzalloc(sizeof(struct nvme_nvm_command), GFP_KERNEL);
	if (!cmd) {
		blk_mq_free_request(rq);
		return -ENOMEM;
	}

	rq->cmd_type = REQ_TYPE_DRV_PRIV;
	rq->ioprio = bio_prio(bio);

	if (bio_has_data(bio))
		rq->nr_phys_segments = bio_phys_segments(q, bio);

	rq->__data_len = bio->bi_iter.bi_size;
	rq->bio = rq->biotail = bio;

	nvme_nvm_rqtocmd(rq, rqd, ns, cmd);

	rq->cmd = (unsigned char *)cmd;
	rq->cmd_len = sizeof(struct nvme_nvm_command);
	rq->special = (void *)0;

	rq->end_io_data = rqd;

	blk_execute_rq_nowait(q, NULL, rq, 0, nvme_nvm_end_io);

	return 0;
}

static int nvme_nvm_erase_block(struct request_queue *q, sector_t block_id)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_nvm_command c = {};

	c.erase.opcode = nvme_nvm_cmd_erase;
	c.erase.nsid = cpu_to_le32(ns->ns_id);
	c.erase.blk_addr = cpu_to_le64(block_id);
	return nvme_submit_sync_cmd(q, (struct nvme_command *)&c, NULL, 0);
}

static void *nvme_nvm_create_dma_pool(struct request_queue *q, char *name)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *dev = ns->dev;

	return dma_pool_create(name, dev->dev, PAGE_SIZE, PAGE_SIZE, 0);
}

static void nvme_nvm_destroy_dma_pool(void *pool)
{
	struct dma_pool *dma_pool = pool;

	dma_pool_destroy(dma_pool);
}

static void *nvme_nvm_dev_dma_alloc(struct request_queue *q, void *pool,
				    gfp_t mem_flags, dma_addr_t *dma_handler)
{
	return dma_pool_alloc(pool, mem_flags, dma_handler);
}

static void nvme_nvm_dev_dma_free(void *pool, void *ppa_list,
							dma_addr_t dma_handler)
{
	dma_pool_free(pool, ppa_list, dma_handler);
}

static struct nvm_dev_ops nvme_nvm_dev_ops = {
	.identify		= nvme_nvm_identify,

	.get_features		= nvme_nvm_get_features,
	.set_responsibility	= nvme_nvm_set_resp,

	.get_l2p_tbl		= nvme_nvm_get_l2p_tbl,

	.set_bb_tbl		= nvme_nvm_set_bb_tbl,
	.get_bb_tbl		= nvme_nvm_get_bb_tbl,

	.submit_io		= nvme_nvm_submit_io,
	.erase_block		= nvme_nvm_erase_block,

	.create_dma_pool	= nvme_nvm_create_dma_pool,
	.destroy_dma_pool	= nvme_nvm_destroy_dma_pool,
	.dev_dma_alloc		= nvme_nvm_dev_dma_alloc,
	.dev_dma_free		= nvme_nvm_dev_dma_free,

	.max_phys_sect		= 64,
};

int nvme_nvm_register(struct request_queue *q, char *disk_name)
{
	return nvm_register(q, disk_name, &nvme_nvm_dev_ops);
}

void nvme_nvm_unregister(char *disk_name)
{
	nvm_unregister(disk_name);
}

int nvme_nvm_ns_supported(struct nvme_ns *ns, struct nvme_id_ns *id)
{
	struct nvme_dev *dev = ns->dev;
	struct pci_dev *pdev = to_pci_dev(dev->dev);

	/* QEMU NVMe simulator - LightNVM detection*/
	if (pdev->vendor == PCI_VENDOR_ID_INTEL && pdev->device == 0x5845 &&
							id->vs[0] == 0x1)
		return 1;

	/* CNEX Labs */
	if (pdev->vendor == 0x1d1d && pdev->device == 0x2807)
		return 1;

	return 0;
}
#else
int nvme_nvm_register(struct request_queue *q, char *disk_name)
{
	return 0;
}
void nvme_nvm_unregister(char *disk_name) {};
int nvme_nvm_ns_supported(struct nvme_ns *ns, struct nvme_id_ns *id)
{
	return 0;
}
#endif /* CONFIG_NVM */
