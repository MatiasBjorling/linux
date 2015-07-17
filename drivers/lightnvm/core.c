/*
 * core.c - Open-channel SSD integration core
 *
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

#include <linux/lightnvm.h>

static LIST_HEAD(_targets);
static LIST_HEAD(_bms);
static DECLARE_RWSEM(_lock);

struct nvm_target_type *nvm_find_target_type(const char *name)
{
	struct nvm_target_type *tt;

	list_for_each_entry(tt, &_targets, list)
		if (!strcmp(name, tt->name))
			return tt;

	return NULL;
}

int nvm_register_target(struct nvm_target_type *tt)
{
	int ret = 0;

	down_write(&_lock);
	if (nvm_find_target_type(tt->name))
		ret = -EEXIST;
	else
		list_add(&tt->list, &_targets);
	up_write(&_lock);

	return ret;
}
EXPORT_SYMBOL(nvm_register_target);

void nvm_unregister_target(struct nvm_target_type *tt)
{
	if (!tt)
		return;

	down_write(&_lock);
	list_del(&tt->list);
	up_write(&_lock);
}
EXPORT_SYMBOL(nvm_unregister_target);

struct nvm_bm_type *nvm_find_bm_type(const char *name)
{
	struct nvm_bm_type *bt;

	list_for_each_entry(bt, &_bms, list)
		if (!strcmp(name, bt->name))
			return bt;

	return NULL;
}

int nvm_register_bm(struct nvm_bm_type *bt)
{
	int ret = 0;

	down_write(&_lock);
	if (nvm_find_bm_type(bt->name))
		ret = -EEXIST;
	else
		list_add(&bt->list, &_bms);
	up_write(&_lock);

	return ret;
}
EXPORT_SYMBOL(nvm_register_bm);

void nvm_unregister_bm(struct nvm_bm_type *bt)
{
	if (!bt)
		return;

	down_write(&_lock);
	list_del(&bt->list);
	up_write(&_lock);
}
EXPORT_SYMBOL(nvm_unregister_bm);

/* use nvm_lun_[get/put]_block to administer the blocks in use for each lun.
 * Whenever a block is in used by an append point, we store it within the
 * used_list. We then move it back when its free to be used by another append
 * point.
 *
 * The newly claimed block is always added to the back of used_list. As we
 * assume that the start of used list is the oldest block, and therefore
 * more likely to contain invalidated pages.
 */
struct nvm_block *nvm_get_blk(struct nvm_dev *dev, struct nvm_lun *lun,
							unsigned long flags)
{
	return dev->bm->get_blk(dev, lun, flags);
}
EXPORT_SYMBOL(nvm_get_blk);

/* We assume that all valid pages have already been moved when added back to the
 * free list. We add it last to allow round-robin use of all pages. Thereby
 * provide simple (naive) wear-leveling.
 */
void nvm_put_blk(struct nvm_dev *dev, struct nvm_block *blk)
{
	return dev->bm->put_blk(dev, blk);
}
EXPORT_SYMBOL(nvm_put_blk);

sector_t nvm_alloc_addr(struct nvm_block *block)
{
	sector_t addr = ADDR_EMPTY;

	spin_lock(&block->lock);
	if (block_is_full(block))
		goto out;

	addr = block_to_addr(block) + block->next_page;

	block->next_page++;
out:
	spin_unlock(&block->lock);
	return addr;
}
EXPORT_SYMBOL(nvm_alloc_addr);

int nvm_submit_io(struct nvm_dev *dev, struct bio *bio, struct nvm_rq *rqdata,
						struct nvm_target_instance *ins)
{
	return dev->bm->submit_io(dev, bio, rqdata, ins);
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
	list_for_each_entry(bt, &_bms, list) {
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

	pr_info("nvm: luns: %u blocks: %lu sector size: %d configured\n",
			dev->nr_luns, dev->total_blocks, dev->sector_size);

	return 0;
err:
	nvm_free(dev);
	pr_err("nvm: failed to initialize nvm\n");
	return ret;
}

void nvm_exit(struct nvm_dev *dev)
{
	nvm_free(dev);

	pr_info("nvm: successfully unloaded\n");
}

static int nvm_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
							unsigned long arg)
{
	return 0;
}

static int nvm_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void nvm_release(struct gendisk *disk, fmode_t mode)
{
}

static const struct block_device_operations nvm_fops = {
	.owner		= THIS_MODULE,
	.ioctl		= nvm_ioctl,
	.open		= nvm_open,
	.release	= nvm_release,
};

static int nvm_create_target(struct gendisk *bdisk, char *ttname, char *tname,
						int lun_begin, int lun_end)
{
	struct request_queue *qqueue = bdisk->queue;
	struct nvm_dev *qnvm = bdisk->nvm;
	struct request_queue *tqueue;
	struct gendisk *tdisk;
	struct nvm_target_type *tt;
	struct nvm_target *t;
	void *targetdata;

	tt = nvm_find_target_type(ttname);
	if (!tt) {
		pr_err("nvm: target type %s not found\n", ttname);
		return -EINVAL;
	}

	down_write(&_lock);
	list_for_each_entry(t, &qnvm->online_targets, list) {
		if (!strcmp(tname, t->disk->disk_name)) {
			pr_err("nvm: target name already exists.\n");
			up_write(&_lock);
			return -EINVAL;
		}
	}
	up_write(&_lock);

	t = kmalloc(sizeof(struct nvm_target), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	tqueue = blk_alloc_queue_node(GFP_KERNEL, qqueue->node);
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

	targetdata = tt->init(bdisk, tdisk, lun_begin, lun_end);
	if (IS_ERR(targetdata))
		goto err_init;

	tdisk->private_data = targetdata;
	tqueue->queuedata = targetdata;

	/* does not yet support multi-page IOs. */
	blk_queue_max_hw_sectors(tqueue, 8);

	set_capacity(tdisk, tt->capacity(targetdata));
	add_disk(tdisk);

	t->type = tt;
	t->disk = tdisk;

	down_write(&_lock);
	list_add_tail(&t->list, &qnvm->online_targets);
	up_write(&_lock);

	return 0;
err_init:
	put_disk(tdisk);
err_queue:
	blk_cleanup_queue(tqueue);
err_t:
	kfree(t);
	return -ENOMEM;
}

/* _lock must be taken */
static void nvm_remove_target(struct nvm_target *t)
{
	struct nvm_target_type *tt = t->type;
	struct gendisk *tdisk = t->disk;
	struct request_queue *q = tdisk->queue;

	del_gendisk(tdisk);
	if (tt->exit)
		tt->exit(tdisk->private_data);
	blk_cleanup_queue(q);

	put_disk(tdisk);

	list_del(&t->list);
	kfree(t);
}

static ssize_t free_blocks_show(struct device *d, struct device_attribute *attr,
		char *page)
{
	struct gendisk *disk = dev_to_disk(d);
	struct nvm_dev *dev = disk->nvm;
	char *page_start = page;

	if (dev->bm)
		dev->bm->free_blocks_print(dev, page);

	return page - page_start;
}

DEVICE_ATTR_RO(free_blocks);

static ssize_t configure_store(struct device *d, struct device_attribute *attr,
						const char *buf, size_t cnt)
{
	struct gendisk *disk = dev_to_disk(d);
	struct nvm_dev *dev = disk->nvm;
	char name[255], ttname[255];
	int lun_begin, lun_end, ret;

	if (cnt >= 255)
		return -EINVAL;

	if (!dev->bm) {
		pr_err("nvm: no bm backend configured for this device.\n");
		return -EINVAL;
	}

	ret = sscanf(buf, "%s %s %u:%u", name, ttname, &lun_begin, &lun_end);
	if (ret != 4) {
		pr_err("nvm: configure must be in the format of \"name targetname lun_begin:lun_end\".\n");
		return -EINVAL;
	}

	if (lun_begin > lun_end || lun_end > dev->nr_luns) {
		pr_err("nvm: lun out of bound (%u:%u > %u)\n",
					lun_begin, lun_end, dev->nr_luns);
		return -EINVAL;
	}

	ret = nvm_create_target(disk, name, ttname, lun_begin, lun_end);
	if (ret)
		pr_err("nvm: configure disk failed\n");

	return cnt;
}
DEVICE_ATTR_WO(configure);

static ssize_t remove_store(struct device *d, struct device_attribute *attr,
						const char *buf, size_t cnt)
{
	struct gendisk *disk = dev_to_disk(d);
	struct nvm_dev *dev = disk->nvm;
	struct nvm_target *t = NULL;
	char tname[255];
	int ret;

	if (cnt >= 255)
		return -EINVAL;

	ret = sscanf(buf, "%s", tname);
	if (ret != 1) {
		pr_err("nvm: remove use the following format \"targetname\".\n");
		return -EINVAL;
	}

	down_write(&_lock);
	list_for_each_entry(t, &dev->online_targets, list) {
		if (!strcmp(tname, t->disk->disk_name)) {
			nvm_remove_target(t);
			ret = 0;
			break;
		}
	}
	up_write(&_lock);

	if (ret)
		pr_err("nvm: target \"%s\" doesn't exist.\n", tname);

	return cnt;
}
DEVICE_ATTR_WO(remove);

static struct attribute *nvm_attrs[] = {
	&dev_attr_free_blocks.attr,
	&dev_attr_configure.attr,
	&dev_attr_remove.attr,
	NULL,
};

static struct attribute_group nvm_attribute_group = {
	.name = "lightnvm",
	.attrs = nvm_attrs,
};

int nvm_attach_sysfs(struct gendisk *disk)
{
	struct device *dev = disk_to_dev(disk);
	int ret;

	if (!disk->nvm)
		return 0;

	ret = sysfs_update_group(&dev->kobj, &nvm_attribute_group);
	if (ret)
		return ret;

	kobject_uevent(&dev->kobj, KOBJ_CHANGE);

	return 0;
}
EXPORT_SYMBOL(nvm_attach_sysfs);

void nvm_remove_sysfs(struct gendisk *disk)
{
	struct device *dev = disk_to_dev(disk);

	sysfs_remove_group(&dev->kobj, &nvm_attribute_group);
}

int nvm_register(struct request_queue *q, struct gendisk *disk,
							struct nvm_dev_ops *ops)
{
	struct nvm_dev *nvm;
	int ret;

	if (!ops->identify || !ops->get_features)
		return -EINVAL;

	nvm = kzalloc(sizeof(struct nvm_dev), GFP_KERNEL);
	if (!nvm)
		return -ENOMEM;

	nvm->q = q;
	nvm->ops = ops;

	ret = nvm_init(nvm);
	if (ret)
		goto err_init;

	disk->nvm = nvm;

	return 0;
err_init:
	kfree(nvm);
	return ret;
}
EXPORT_SYMBOL(nvm_register);

void nvm_unregister(struct gendisk *disk)
{
	if (!disk->nvm)
		return;

	nvm_remove_sysfs(disk);

	nvm_exit(disk->nvm);
}
EXPORT_SYMBOL(nvm_unregister);
