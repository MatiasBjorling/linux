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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/sem.h>
#include <linux/bitmap.h>
#include <linux/module.h>

#include <linux/lightnvm.h>

static LIST_HEAD(nvm_targets);
static LIST_HEAD(nvm_bms);
static LIST_HEAD(nvm_devices);
static DECLARE_RWSEM(nvm_lock);

struct nvm_tgt_type *nvm_find_target_type(const char *name)
{
	struct nvm_tgt_type *tt;

	list_for_each_entry(tt, &nvm_targets, list)
		if (!strcmp(name, tt->name))
			return tt;

	return NULL;
}

int nvm_register_target(struct nvm_tgt_type *tt)
{
	int ret = 0;

	down_write(&nvm_lock);
	if (nvm_find_target_type(tt->name))
		ret = -EEXIST;
	else
		list_add(&tt->list, &nvm_targets);
	up_write(&nvm_lock);

	return ret;
}
EXPORT_SYMBOL(nvm_register_target);

void nvm_unregister_target(struct nvm_tgt_type *tt)
{
	if (!tt)
		return;

	down_write(&nvm_lock);
	list_del(&tt->list);
	up_write(&nvm_lock);
}
EXPORT_SYMBOL(nvm_unregister_target);

void *nvm_alloc_ppalist(struct nvm_dev *dev, gfp_t mem_flags,
							dma_addr_t *dma_handler)
{
	return dev->ops->alloc_ppalist(dev->q, dev->ppalist_pool, mem_flags,
								dma_handler);
}
EXPORT_SYMBOL(nvm_alloc_ppalist);

void nvm_free_ppalist(struct nvm_dev *dev, void *ppa_list,
							dma_addr_t dma_handler)
{
	dev->ops->free_ppalist(dev->ppalist_pool, ppa_list, dma_handler);
}
EXPORT_SYMBOL(nvm_free_ppalist);

struct nvm_bm_type *nvm_find_bm_type(const char *name)
{
	struct nvm_bm_type *bt;

	list_for_each_entry(bt, &nvm_bms, list)
		if (!strcmp(name, bt->name))
			return bt;

	return NULL;
}

int nvm_register_bm(struct nvm_bm_type *bt)
{
	int ret = 0;

	down_write(&nvm_lock);
	if (nvm_find_bm_type(bt->name))
		ret = -EEXIST;
	else
		list_add(&bt->list, &nvm_bms);
	up_write(&nvm_lock);

	return ret;
}
EXPORT_SYMBOL(nvm_register_bm);

void nvm_unregister_bm(struct nvm_bm_type *bt)
{
	if (!bt)
		return;

	down_write(&nvm_lock);
	list_del(&bt->list);
	up_write(&nvm_lock);
}
EXPORT_SYMBOL(nvm_unregister_bm);

struct nvm_dev *nvm_find_nvm_dev(const char *name)
{
	struct nvm_dev *dev;

	list_for_each_entry(dev, &nvm_devices, devices)
		if (!strcmp(name, dev->name))
			return dev;

	return NULL;
}

struct nvm_block *nvm_get_blk(struct nvm_dev *dev, struct nvm_lun *lun,
							unsigned long flags)
{
	return dev->bm->get_blk(dev, lun, flags);
}
EXPORT_SYMBOL(nvm_get_blk);

/* Assumes that all valid pages have already been moved on release to bm */
void nvm_put_blk(struct nvm_dev *dev, struct nvm_block *blk)
{
	return dev->bm->put_blk(dev, blk);
}
EXPORT_SYMBOL(nvm_put_blk);

int nvm_submit_io(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	return dev->ops->submit_io(dev->q, rqd);
}
EXPORT_SYMBOL(nvm_submit_io);

/* Send erase command to device */
int nvm_erase_blk(struct nvm_dev *dev, struct nvm_block *blk)
{
	return dev->bm->erase_blk(dev, blk);
}
EXPORT_SYMBOL(nvm_erase_blk);

static void nvm_core_free(struct nvm_dev *dev)
{
	kfree(dev->identity.chnls);
	kfree(dev);
}

static int nvm_core_init(struct nvm_dev *dev)
{
	dev->nr_luns = dev->identity.nchannels;
	dev->sector_size = EXPOSED_PAGE_SIZE;
	INIT_LIST_HEAD(&dev->online_targets);

	return 0;
}

static void nvm_free(struct nvm_dev *dev)
{
	if (!dev)
		return;

	if (dev->bm)
		dev->bm->unregister_bm(dev);

	nvm_core_free(dev);
}

int nvm_validate_features(struct nvm_dev *dev)
{
	struct nvm_get_features gf;
	int ret;

	ret = dev->ops->get_features(dev->q, &gf);
	if (ret)
		return ret;

	dev->features = gf;

	return 0;
}

int nvm_validate_responsibility(struct nvm_dev *dev)
{
	if (!dev->ops->set_responsibility)
		return 0;

	return dev->ops->set_responsibility(dev->q, 0);
}

int nvm_init(struct nvm_dev *dev)
{
	struct nvm_bm_type *bt;
	int ret = 0;

	if (!dev->q || !dev->ops)
		return -EINVAL;

	if (dev->ops->identify(dev->q, &dev->identity)) {
		pr_err("nvm: device could not be identified\n");
		ret = -EINVAL;
		goto err;
	}

	pr_debug("nvm dev: ver %u type %u chnls %u\n",
			dev->identity.ver_id,
			dev->identity.nvm_type,
			dev->identity.nchannels);

	ret = nvm_validate_features(dev);
	if (ret) {
		pr_err("nvm: disk features are not supported.");
		goto err;
	}

	ret = nvm_validate_responsibility(dev);
	if (ret) {
		pr_err("nvm: disk responsibilities are not supported.");
		goto err;
	}

	ret = nvm_core_init(dev);
	if (ret) {
		pr_err("nvm: could not initialize core structures.\n");
		goto err;
	}

	if (!dev->nr_luns) {
		pr_err("nvm: device did not expose any luns.\n");
		goto err;
	}

	/* register with device with a supported BM */
	list_for_each_entry(bt, &nvm_bms, list) {
		ret = bt->register_bm(dev);
		if (ret < 0)
			goto err; /* initialization failed */
		if (ret > 0) {
			dev->bm = bt;
			break; /* successfully initialized */
		}
	}

	if (!ret) {
		pr_info("nvm: no compatible bm was found.\n");
		return 0;
	}

	pr_info("nvm: registered %s with luns: %u blocks: %lu sector size: %d\n",
		dev->name, dev->nr_luns, dev->total_blocks, dev->sector_size);

	return 0;
err:
	nvm_free(dev);
	pr_err("nvm: failed to initialize nvm\n");
	return ret;
}

void nvm_exit(struct nvm_dev *dev)
{
	if (dev->ppalist_pool)
		dev->ops->destroy_ppa_pool(dev->ppalist_pool);
	nvm_free(dev);

	pr_info("nvm: successfully unloaded\n");
}

static const struct block_device_operations nvm_fops = {
	.owner		= THIS_MODULE,
};

static int nvm_create_target(struct nvm_dev *dev, char *ttname, char *tname,
						int lun_begin, int lun_end)
{
	struct request_queue *tqueue;
	struct gendisk *tdisk;
	struct nvm_tgt_type *tt;
	struct nvm_target *t;
	void *targetdata;

	tt = nvm_find_target_type(ttname);
	if (!tt) {
		pr_err("nvm: target type %s not found\n", ttname);
		return -EINVAL;
	}

	down_write(&nvm_lock);
	list_for_each_entry(t, &dev->online_targets, list) {
		if (!strcmp(tname, t->disk->disk_name)) {
			pr_err("nvm: target name already exists.\n");
			up_write(&nvm_lock);
			return -EINVAL;
		}
	}
	up_write(&nvm_lock);

	t = kmalloc(sizeof(struct nvm_target), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	tqueue = blk_alloc_queue_node(GFP_KERNEL, dev->q->node);
	if (!tqueue)
		goto err_t;
	blk_queue_make_request(tqueue, tt->make_rq);

	tdisk = alloc_disk(0);
	if (!tdisk)
		goto err_queue;

	sprintf(tdisk->disk_name, "%s", tname);
	tdisk->flags = GENHD_FL_EXT_DEVT;
	tdisk->major = 0;
	tdisk->first_minor = 0;
	tdisk->fops = &nvm_fops;
	tdisk->queue = tqueue;

	targetdata = tt->init(dev, tdisk, lun_begin, lun_end);
	if (IS_ERR(targetdata))
		goto err_init;

	tdisk->private_data = targetdata;
	tqueue->queuedata = targetdata;

	blk_queue_max_hw_sectors(tqueue, 8 * dev->ops->max_phys_sect);

	set_capacity(tdisk, tt->capacity(targetdata));
	add_disk(tdisk);

	t->type = tt;
	t->disk = tdisk;

	down_write(&nvm_lock);
	list_add_tail(&t->list, &dev->online_targets);
	up_write(&nvm_lock);

	return 0;
err_init:
	put_disk(tdisk);
err_queue:
	blk_cleanup_queue(tqueue);
err_t:
	kfree(t);
	return -ENOMEM;
}

static void nvm_remove_target(struct nvm_target *t)
{
	struct nvm_tgt_type *tt = t->type;
	struct gendisk *tdisk = t->disk;
	struct request_queue *q = tdisk->queue;

	lockdep_assert_held(&nvm_lock);

	del_gendisk(tdisk);
	if (tt->exit)
		tt->exit(tdisk->private_data);

	blk_cleanup_queue(q);

	put_disk(tdisk);

	list_del(&t->list);
	kfree(t);
}

static int nvm_configure_show(const char *val)
{
	struct nvm_dev *dev;
	char opcode, devname[DISK_NAME_LEN];
	int ret;

	ret = sscanf(val, "%c %s", &opcode, devname);
	if (ret != 2) {
		pr_err("nvm: invalid command. Use \"opcode devicename\".\n");
		return -EINVAL;
	}

	dev = nvm_find_nvm_dev(devname);
	if (!dev) {
		pr_err("nvm: device not found\n");
		return -EINVAL;
	}

	if (!dev->bm)
		return 0;

	dev->bm->free_blocks_print(dev);

	return 0;
}

static int nvm_configure_del(const char *val)
{
	struct nvm_target *t = NULL;
	struct nvm_dev *dev;
	char opcode, tname[255];
	int ret;

	ret = sscanf(val, "%c %s", &opcode, tname);
	if (ret != 2) {
		pr_err("nvm: invalid command. Use \"d targetname\".\n");
		return -EINVAL;
	}

	down_write(&nvm_lock);
	list_for_each_entry(dev, &nvm_devices, devices)
		list_for_each_entry(t, &dev->online_targets, list) {
			if (!strcmp(tname, t->disk->disk_name)) {
				nvm_remove_target(t);
				ret = 0;
				break;
			}
		}
	up_write(&nvm_lock);

	if (ret) {
		pr_err("nvm: target \"%s\" doesn't exist.\n", tname);
		return -EINVAL;
	}

	return 0;
}

static int nvm_configure_add(const char *val)
{
	struct nvm_dev *dev;
	char opcode, devname[DISK_NAME_LEN], tgtengine[255], tname[255];
	int lun_begin, lun_end, ret;

	ret = sscanf(val, "%c %s %s %s %u:%u", &opcode, devname, tgtengine,
						tname, &lun_begin, &lun_end);
	if (ret != 6) {
		pr_err("nvm: invalid command. Use \"opcode device name tgtengine lun_begin:lun_end\".\n");
		return -EINVAL;
	}

	dev = nvm_find_nvm_dev(devname);
	if (!dev) {
		pr_err("nvm: device not found\n");
		return -EINVAL;
	}

	if (lun_begin > lun_end || lun_end > dev->nr_luns) {
		pr_err("nvm: lun out of bound (%u:%u > %u)\n",
					lun_begin, lun_end, dev->nr_luns);
		return -EINVAL;
	}

	return nvm_create_target(dev, tname, tgtengine, lun_begin, lun_end);
}

/* Exposes administrative interface through /sys/module/lnvm/configure_by_str */
static int nvm_configure_by_str_event(const char *val,
					const struct kernel_param *kp)
{
	char opcode;
	int ret;

	ret = sscanf(val, "%c", &opcode);
	if (ret != 1) {
		pr_err("nvm: configure must be in the format of \"opcode ...\"\n");
		return -EINVAL;
	}

	switch (opcode) {
	case 'a':
		return nvm_configure_add(val);
	case 'd':
		return nvm_configure_del(val);
	case 's':
		return nvm_configure_show(val);
	default:
		pr_err("nvm: invalid opcode.\n");
		return -EINVAL;
	}

	return 0;
}

static int nvm_configure_get(char *buf, const struct kernel_param *kp)
{
	int sz = 0;
	char *buf_start = buf;
	struct nvm_dev *dev;

	buf += sprintf(buf, "available devices:\n");
	down_write(&nvm_lock);
	list_for_each_entry(dev, &nvm_devices, devices) {
		if (sz > 4095 - DISK_NAME_LEN)
			break;
		buf += sprintf(buf, " %s\n", dev->name);
	}
	up_write(&nvm_lock);

	return buf - buf_start - 1;
}

static const struct kernel_param_ops nvm_configure_by_str_event_param_ops = {
	.set	= nvm_configure_by_str_event,
	.get	= nvm_configure_get,
};

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX	"lnvm."

module_param_cb(configure_debug, &nvm_configure_by_str_event_param_ops, NULL,
									0644);

int nvm_register(struct request_queue *q, char *disk_name,
							struct nvm_dev_ops *ops)
{
	struct nvm_dev *dev;
	int ret;

	if (!ops->identify || !ops->get_features)
		return -EINVAL;

	dev = kzalloc(sizeof(struct nvm_dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->q = q;
	dev->ops = ops;
	strncpy(dev->name, disk_name, DISK_NAME_LEN);

	ret = nvm_init(dev);
	if (ret)
		goto err_init;

	down_write(&nvm_lock);
	list_add(&dev->devices, &nvm_devices);
	up_write(&nvm_lock);

	if (dev->ops->max_phys_sect > 256) {
		pr_info("nvm: maximum number of sectors supported in target is 255. max_phys_sect set to 255\n");
		dev->ops->max_phys_sect = 255;
	}

	if (dev->ops->max_phys_sect > 1) {
		dev->ppalist_pool = dev->ops->create_ppa_pool(dev->q);
		if (!dev->ppalist_pool) {
			pr_err("nvm: could not create ppa pool\n");
			return -ENOMEM;
		}
	}

	return 0;
err_init:
	kfree(dev);
	return ret;
}
EXPORT_SYMBOL(nvm_register);

void nvm_unregister(char *disk_name)
{
	struct nvm_dev *dev = nvm_find_nvm_dev(disk_name);

	if (!dev) {
		pr_err("nvm: could not find device %s on unregister\n",
								disk_name);
		return;
	}

	nvm_exit(dev);

	down_write(&nvm_lock);
	list_del(&dev->devices);
	up_write(&nvm_lock);
}
EXPORT_SYMBOL(nvm_unregister);
