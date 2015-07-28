/*
 * derived from Jens Axboe's block/null_blk.c
 */

#include <linux/module.h>

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/blk-mq.h>
#include <linux/hrtimer.h>
#include <linux/lightnvm.h>

static struct kmem_cache *ppa_cache;
struct nulln_cmd {
	struct llist_node ll_list;
	struct request *rq;
};

struct nulln {
	struct list_head list;
	unsigned int index;
	struct request_queue *q;
	struct blk_mq_tag_set tag_set;
	struct hrtimer timer;
	char disk_name[DISK_NAME_LEN];
};

static LIST_HEAD(nulln_list);
static struct mutex nulln_lock;
static int nulln_indexes;

struct completion_queue {
	struct llist_head list;
	struct hrtimer timer;
};

/*
 * These are per-cpu for now, they will need to be configured by the
 * complete_queues parameter and appropriately mapped.
 */
static DEFINE_PER_CPU(struct completion_queue, null_comp_queues);

enum {
	NULL_IRQ_NONE		= 0,
	NULL_IRQ_SOFTIRQ	= 1,
	NULL_IRQ_TIMER		= 2,
};

static int submit_queues;
module_param(submit_queues, int, S_IRUGO);
MODULE_PARM_DESC(submit_queues, "Number of submission queues");

static int home_node = NUMA_NO_NODE;
module_param(home_node, int, S_IRUGO);
MODULE_PARM_DESC(home_node, "Home node for the device");

static int null_param_store_val(const char *str, int *val, int min, int max)
{
	int ret, new_val;

	ret = kstrtoint(str, 10, &new_val);
	if (ret)
		return -EINVAL;

	if (new_val < min || new_val > max)
		return -EINVAL;

	*val = new_val;
	return 0;
}

static int gb = 250;
module_param(gb, int, S_IRUGO);
MODULE_PARM_DESC(gb, "Size in GB");

static int bs = 4096;
module_param(bs, int, S_IRUGO);
MODULE_PARM_DESC(bs, "Block size (in bytes)");

static int nr_devices = 1;
module_param(nr_devices, int, S_IRUGO);
MODULE_PARM_DESC(nr_devices, "Number of devices to register");

static int irqmode = NULL_IRQ_SOFTIRQ;

static int null_set_irqmode(const char *str, const struct kernel_param *kp)
{
	return null_param_store_val(str, &irqmode, NULL_IRQ_NONE,
					NULL_IRQ_TIMER);
}

static const struct kernel_param_ops null_irqmode_param_ops = {
	.set	= null_set_irqmode,
	.get	= param_get_int,
};

device_param_cb(irqmode, &null_irqmode_param_ops, &irqmode, S_IRUGO);
MODULE_PARM_DESC(irqmode, "IRQ completion handler. 0-none, 1-softirq, 2-timer");

static int completion_nsec = 10000;
module_param(completion_nsec, int, S_IRUGO);
MODULE_PARM_DESC(completion_nsec, "Time in ns to complete a request in hardware. Default: 10,000ns");

static int hw_queue_depth = 64;
module_param(hw_queue_depth, int, S_IRUGO);
MODULE_PARM_DESC(hw_queue_depth, "Queue depth for each hardware queue. Default: 64");

static bool use_per_node_hctx;
module_param(use_per_node_hctx, bool, S_IRUGO);
MODULE_PARM_DESC(use_per_node_hctx, "Use per-node allocation for hardware context queues. Default: false");

static int num_channels = 1;
module_param(num_channels, int, S_IRUGO);
MODULE_PARM_DESC(num_channels, "Number of channels to be exposed. Default: 1");

static enum hrtimer_restart null_cmd_timer_expired(struct hrtimer *timer)
{
	struct completion_queue *cq;
	struct llist_node *entry;
	struct nulln_cmd *cmd;

	cq = &per_cpu(null_comp_queues, smp_processor_id());

	while ((entry = llist_del_all(&cq->list)) != NULL) {
		entry = llist_reverse_order(entry);
		do {
			cmd = container_of(entry, struct nulln_cmd, ll_list);
			entry = entry->next;
			blk_mq_end_request(cmd->rq, 0);

			if (cmd->rq) {
				struct request_queue *q = cmd->rq->q;

				if (!q->mq_ops && blk_queue_stopped(q)) {
					spin_lock(q->queue_lock);
					if (blk_queue_stopped(q))
						blk_start_queue(q);
					spin_unlock(q->queue_lock);
				}
			}
		} while (entry);
	}

	return HRTIMER_NORESTART;
}

static void null_cmd_end_timer(struct nulln_cmd *cmd)
{
	struct completion_queue *cq = &per_cpu(null_comp_queues, get_cpu());

	cmd->ll_list.next = NULL;
	if (llist_add(&cmd->ll_list, &cq->list)) {
		ktime_t kt = ktime_set(0, completion_nsec);

		hrtimer_start(&cq->timer, kt, HRTIMER_MODE_REL_PINNED);
	}

	put_cpu();
}

static void null_softirq_done_fn(struct request *rq)
{
	blk_mq_end_request(rq, 0);
}

static inline void null_handle_cmd(struct nulln_cmd *cmd)
{
	/* Complete IO by inline, softirq or timer */
	switch (irqmode) {
	case NULL_IRQ_SOFTIRQ:
	case NULL_IRQ_NONE:
		blk_mq_complete_request(cmd->rq, cmd->rq->errors);
		break;
	case NULL_IRQ_TIMER:
		null_cmd_end_timer(cmd);
		break;
	}
}

static int null_id(struct request_queue *q, struct nvm_id *id)
{
	sector_t size = gb * 1024 * 1024 * 1024ULL;
	unsigned long per_chnl_size =
				size / bs / num_channels;
	struct nvm_id_group *grp;

	id->ver_id = 0x1;
	id->vmnt = 0;
	id->cgrps = 1;
	id->cap = 0x3;
	id->dom = 0x1;
	id->ppat = NVM_ADDRMODE_LINEAR;

	grp = &id->groups[0];
	grp->mtype = 0;
	grp->fmtype = 1;
	grp->num_ch = 1;
	grp->num_lun = num_channels;
	grp->num_pln = 1;
	grp->num_blk = per_chnl_size / 256;
	grp->num_pg = 256;
	grp->fpg_sz = bs;
	grp->csecs = bs;
	grp->trdt = 25000;
	grp->trdm = 25000;
	grp->tprt = 500000;
	grp->tprm = 500000;
	grp->tbet = 1500000;
	grp->tbem = 1500000;
	grp->mpos = 0x010101; /* single plane rwe */
	grp->cpar = hw_queue_depth;

	return 0;
}

static void null_end_io(struct request *rq, int error)
{
	struct nvm_rq *rqd = rq->end_io_data;
	struct nvm_dev *dev = rqd->dev;

	dev->mt->end_io(rqd, error);

	blk_put_request(rq);
}

static int null_submit_io(struct request_queue *q, struct nvm_rq *rqd)
{
	struct request *rq;
	struct bio *bio = rqd->bio;

	rq = blk_mq_alloc_request(q, bio_rw(bio), GFP_KERNEL, 0);
	if (IS_ERR(rq))
		return -ENOMEM;

	rq->cmd_type = REQ_TYPE_DRV_PRIV;
	rq->__sector = bio->bi_iter.bi_sector;
	rq->ioprio = bio_prio(bio);

	if (bio_has_data(bio))
		rq->nr_phys_segments = bio_phys_segments(q, bio);

	rq->__data_len = bio->bi_iter.bi_size;
	rq->bio = rq->biotail = bio;

	rq->end_io_data = rqd;

	blk_execute_rq_nowait(q, NULL, rq, 0, null_end_io);

	return 0;
}

static void *null_create_dma_pool(struct request_queue *q, char *name)
{
	mempool_t *virtmem_pool;

	ppa_cache = kmem_cache_create(name, PAGE_SIZE, 0, 0, NULL);
	if (!ppa_cache) {
		pr_err("null_nvm: Unable to create kmem cache\n");
		return NULL;
	}

	virtmem_pool = mempool_create_slab_pool(64, ppa_cache);
	if (!virtmem_pool) {
		pr_err("null_nvm: Unable to create virtual memory pool\n");
		return NULL;
	}

	return virtmem_pool;
}

static void null_destroy_dma_pool(void *pool)
{
	mempool_t *virtmem_pool = pool;

	mempool_destroy(virtmem_pool);
}

static void *null_dev_dma_alloc(struct request_queue *q, void *pool,
				gfp_t mem_flags, dma_addr_t *dma_handler)
{
	return mempool_alloc(pool, mem_flags);
}

static void null_dev_dma_free(void *pool, void *entry, dma_addr_t dma_handler)
{
	mempool_free(entry, pool);
}

static struct nvm_dev_ops nulln_dev_ops = {
	.identity		= null_id,
	.submit_io		= null_submit_io,

	.create_dma_pool	= null_create_dma_pool,
	.destroy_dma_pool	= null_destroy_dma_pool,
	.dev_dma_alloc		= null_dev_dma_alloc,
	.dev_dma_free		= null_dev_dma_free,

	/* Emulate nvme protocol */
	.max_phys_sect		= 64,
};

static int null_queue_rq(struct blk_mq_hw_ctx *hctx,
			 const struct blk_mq_queue_data *bd)
{
	struct nulln_cmd *cmd = blk_mq_rq_to_pdu(bd->rq);

	cmd->rq = bd->rq;

	blk_mq_start_request(bd->rq);

	null_handle_cmd(cmd);
	return BLK_MQ_RQ_QUEUE_OK;
}

static struct blk_mq_ops null_mq_ops = {
	.queue_rq	= null_queue_rq,
	.map_queue	= blk_mq_map_queue,
	.complete	= null_softirq_done_fn,
};

static void null_del_dev(struct nulln *nulln)
{
	list_del_init(&nulln->list);

	nvm_unregister(nulln->disk_name);

	blk_cleanup_queue(nulln->q);
	blk_mq_free_tag_set(&nulln->tag_set);
	kfree(nulln);
}

static int null_add_dev(void)
{
	struct nulln *nulln;
	int rv;

	nulln = kzalloc_node(sizeof(*nulln), GFP_KERNEL, home_node);
	if (!nulln) {
		rv = -ENOMEM;
		goto out;
	}

	if (use_per_node_hctx)
		submit_queues = nr_online_nodes;

	nulln->tag_set.ops = &null_mq_ops;
	nulln->tag_set.nr_hw_queues = submit_queues;
	nulln->tag_set.queue_depth = hw_queue_depth;
	nulln->tag_set.numa_node = home_node;
	nulln->tag_set.cmd_size = sizeof(struct nulln_cmd);
	nulln->tag_set.driver_data = nulln;

	rv = blk_mq_alloc_tag_set(&nulln->tag_set);
	if (rv)
		goto out_free_nulln;

	nulln->q = blk_mq_init_queue(&nulln->tag_set);
	if (IS_ERR(nulln->q)) {
		rv = -ENOMEM;
		goto out_cleanup_tags;
	}

	nulln->q->queuedata = nulln;
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, nulln->q);
	queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, nulln->q);

	mutex_lock(&nulln_lock);
	list_add_tail(&nulln->list, &nulln_list);
	nulln->index = nulln_indexes++;
	mutex_unlock(&nulln_lock);

	blk_queue_logical_block_size(nulln->q, bs);
	blk_queue_physical_block_size(nulln->q, bs);

	sprintf(nulln->disk_name, "nulln%d", nulln->index);

	rv = nvm_register(nulln->q, nulln->disk_name, &nulln_dev_ops);
	if (rv)
		goto out_cleanup_blk_queue;

	return 0;

out_cleanup_blk_queue:
	blk_cleanup_queue(nulln->q);
out_cleanup_tags:
	blk_mq_free_tag_set(&nulln->tag_set);
out_free_nulln:
	kfree(nulln);
out:
	return rv;
}

static int __init null_init(void)
{
	unsigned int i;

	if (bs > PAGE_SIZE) {
		pr_warn("null_nvm: invalid block size\n");
		pr_warn("null_nvm: defaults block size to %lu\n", PAGE_SIZE);
		bs = PAGE_SIZE;
	}

	if (use_per_node_hctx) {
		if (submit_queues < nr_online_nodes) {
			pr_warn("null_nvm: submit_queues param is set to %u.",
							nr_online_nodes);
			submit_queues = nr_online_nodes;
		}
	} else if (submit_queues > nr_cpu_ids)
		submit_queues = nr_cpu_ids;
	else if (!submit_queues)
		submit_queues = 1;

	mutex_init(&nulln_lock);

	/* Initialize a separate list for each CPU for issuing softirqs */
	for_each_possible_cpu(i) {
		struct completion_queue *cq = &per_cpu(null_comp_queues, i);

		init_llist_head(&cq->list);

		if (irqmode != NULL_IRQ_TIMER)
			continue;

		hrtimer_init(&cq->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		cq->timer.function = null_cmd_timer_expired;
	}

	for (i = 0; i < nr_devices; i++) {
		if (null_add_dev())
			return -EINVAL;
	}

	pr_info("null_nvm: module loaded\n");
	return 0;
}

static void __exit null_exit(void)
{
	struct nulln *nulln;

	mutex_lock(&nulln_lock);
	while (!list_empty(&nulln_list)) {
		nulln = list_entry(nulln_list.next, struct nulln, list);
		null_del_dev(nulln);
	}
	mutex_unlock(&nulln_lock);
}

module_init(null_init);
module_exit(null_exit);

MODULE_AUTHOR("Matias Bjorling <mb@lightnvm.io>");
MODULE_LICENSE("GPL");
