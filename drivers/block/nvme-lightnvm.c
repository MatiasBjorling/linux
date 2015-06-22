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

static int init_chnls(struct request_queue *q, struct nvm_id *nvm_id,
						struct nvme_nvm_id *nvme_nvm_id)
{
	struct nvme_nvm_id_chnl *src = nvme_nvm_id->chnls;
	struct nvm_id_chnl *dst = nvm_id->chnls;
	struct nvme_ns *ns = q->queuedata;
	struct nvme_command c = {
		.nvm_identify.opcode = nvme_nvm_admin_identify,
		.nvm_identify.nsid = cpu_to_le32(ns->ns_id),
	};
	unsigned int len = nvm_id->nchannels;
	int i, end, ret, off = 0;

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

		c.nvm_identify.chnl_off = off;

		ret = nvme_submit_sync_cmd(q, &c, nvme_nvm_id, 4096);
		if (ret)
			return ret;
	}
	return 0;
}

static int nvme_nvm_identify(struct request_queue *q, struct nvm_id *nvm_id)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_nvm_id *nvme_nvm_id;
	struct nvme_command c = {
		.nvm_identify.opcode = nvme_nvm_admin_identify,
		.nvm_identify.nsid = cpu_to_le32(ns->ns_id),
		.nvm_identify.chnl_off = 0,
	};
	int ret;

	nvme_nvm_id = kmalloc(4096, GFP_KERNEL);
	if (!nvme_nvm_id)
		return -ENOMEM;

	ret = nvme_submit_sync_cmd(q, &c, nvme_nvm_id, 4096);
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
	struct nvme_command c = {
		.common.opcode = nvme_nvm_admin_get_features,
		.common.nsid = ns->ns_id,
	};
	int sz = sizeof(struct nvm_get_features);
	int ret;
	u64 *resp;

	resp = kmalloc(sz, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	ret = nvme_submit_sync_cmd(q, &c, resp, sz);
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
	struct nvme_command c = {
		.nvm_resp.opcode = nvme_nvm_admin_set_resp,
		.nvm_resp.nsid = cpu_to_le32(ns->ns_id),
		.nvm_resp.resp = cpu_to_le64(resp),
	};

	return nvme_submit_sync_cmd(q, &c, NULL, 0);
}

static int nvme_nvm_get_l2p_tbl(struct request_queue *q, u64 slba, u64 nlb,
				nvm_l2p_update_fn *update_l2p, void *priv)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *dev = ns->dev;
	struct nvme_command c = {
		.nvm_l2p.opcode = nvme_nvm_admin_get_l2p_tbl,
		.nvm_l2p.nsid = cpu_to_le32(ns->ns_id),
	};
	u32 len = queue_max_hw_sectors(q) << 9;
	u64 nlb_pr_rq = len / sizeof(u64);
	u64 cmd_slba = slba;
	void *entries;
	int ret = 0;

	entries = kmalloc(len, GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	while (nlb) {
		u64 cmd_nlb = min_t(u64, nlb_pr_rq, nlb);

		c.nvm_l2p.slba = cmd_slba;
		c.nvm_l2p.nlb = cmd_nlb;

		ret = nvme_submit_sync_cmd(q, &c, entries, len);
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
	struct nvme_command c = {
		.nvm_get_bb.opcode = nvme_nvm_admin_get_bb_tbl,
		.nvm_get_bb.nsid = cpu_to_le32(ns->ns_id),
		.nvm_get_bb.lbb = cpu_to_le32(lunid),
	};
	void *bb_bitmap;
	u16 bb_bitmap_size;
	int ret = 0;

	bb_bitmap_size = ((nr_blocks >> 15) + 1) * PAGE_SIZE;
	bb_bitmap = kmalloc(bb_bitmap_size, GFP_KERNEL);
	if (!bb_bitmap)
		return -ENOMEM;

	bitmap_zero(bb_bitmap, nr_blocks);

	ret = nvme_submit_sync_cmd(q, &c, bb_bitmap, bb_bitmap_size);
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

int nvme_nvm_prep_internal_rq(struct request *rq, struct nvme_ns *ns,
				struct nvme_command *c, struct nvme_iod *iod)
{
	struct nvm_rq *rqdata = &iod->nvmrq;
	struct nvm_internal_cmd *cmd = rq->special;

	if (!cmd)
		return 0;

	if (nvm_prep_rq(rq, rqdata))
		dev_err(ns->dev->dev, "lightnvm: internal cmd failed\n");

	c->nvm_hb_rw.length = cpu_to_le16(
			(blk_rq_bytes(rq) >> ns->lba_shift) - 1);
	c->nvm_hb_rw.nsid = cpu_to_le32(ns->ns_id);
	c->nvm_hb_rw.slba = cpu_to_le64(cmd->phys_lba);
	c->nvm_hb_rw.phys_addr =
		cpu_to_le64(nvme_block_nr(ns, rqdata->phys_sector));

	return 0;
}

static int nvme_nvm_internal_rw(struct request_queue *q,
						struct nvm_internal_cmd *cmd)
{
	struct nvme_command c;

	memset(&c, 0, sizeof(c));

	c.nvm_hb_rw.opcode = (cmd->rw ?
				nvme_nvm_cmd_hb_write : nvme_nvm_cmd_hb_read);

	return __nvme_submit_sync_cmd(q, &c, cmd->buffer, NULL,
						cmd->bufflen, NULL, 30, cmd);
}

static int nvme_nvm_erase_block(struct request_queue *q, sector_t block_id)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_command c = {
		.nvm_erase.opcode = nvme_nvm_cmd_erase,
		.nvm_erase.nsid = cpu_to_le32(ns->ns_id),
		.nvm_erase.blk_addr = cpu_to_le64(block_id),
	};

	return nvme_submit_sync_cmd(q, &c, NULL, 0);
}

static struct nvm_dev_ops nvme_nvm_dev_ops = {
	.identify		= nvme_nvm_identify,
	.get_features		= nvme_nvm_get_features,
	.set_responsibility	= nvme_nvm_set_resp,
	.get_l2p_tbl		= nvme_nvm_get_l2p_tbl,
	.set_bb_tbl		= nvme_nvm_set_bb_tbl,
	.get_bb_tbl		= nvme_nvm_get_bb_tbl,
	.internal_rw		= nvme_nvm_internal_rw,
	.erase_block		= nvme_nvm_erase_block,
};

#else
static struct nvm_dev_ops nvme_nvm_dev_ops;
static nvm_data_rq;

void nvme_nvm_prep_internal_rq(struct request *rq, struct nvme_ns *ns,
			struct nvme_command *c, struct nvme_iod *iod)
{
}
#endif /* CONFIG_NVM */

int nvme_nvm_register(struct request_queue *q, struct gendisk *disk)
{
	return nvm_register(q, disk, &nvme_nvm_dev_ops);
}

