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
static DEFINE_PER_CPU(struct completion_queue, completion_queues);

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

	cq = &per_cpu(completion_queues, smp_processor_id());

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
	struct completion_queue *cq = &per_cpu(completion_queues, get_cpu());

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
		blk_mq_complete_request(cmd->rq);
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
	struct nvm_id_chnl *chnl;
	int i;

	id->ver_id = 0x1;
	id->nvm_type = NVM_NVMT_BLK;
	id->nchannels = num_channels;

	id->chnls = kmalloc_array(id->nchannels, sizeof(struct nvm_id_chnl),
								GFP_KERNEL);
	if (!id->chnls)
		return -ENOMEM;

	for (i = 0; i < id->nchannels; i++) {
		chnl = &id->chnls[i];
		chnl->queue_size = hw_queue_depth;
		chnl->gran_read = bs;
		chnl->gran_write = bs;
		chnl->gran_erase = bs * 256;
		chnl->oob_size = 0;
		chnl->t_r = chnl->t_sqr = 25000; /* 25us */
		chnl->t_w = chnl->t_sqw = 500000; /* 500us */
		chnl->t_e = 1500000; /* 1.500us */
		chnl->io_sched = NVM_IOSCHED_CHANNEL;
		chnl->laddr_begin = per_chnl_size * i;
		chnl->laddr_end = per_chnl_size * (i + 1) - 1;
	}

	return 0;
}

static int null_get_features(struct request_queue *q,
						struct nvm_get_features *gf)
{
	gf->rsp = NVM_RSP_L2P;
	gf->ext = 0;

	return 0;
}

static void null_end_io(struct request *rq, int error)
{
	struct nvm_rq *rqd = rq->end_io_data;
	struct nvm_tgt_instance *ins = rqd->ins;

	ins->tt->end_io(rq->end_io_data, error);

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

static void *null_create_ppa_pool(struct request_queue *q)
{
	mempool_t *virtmem_pool;

	ppa_cache = kmem_cache_create("ppa_list", PAGE_SIZE, 0, 0, NULL);
	if (!ppa_cache) {
		pr_err("null_nvm: Unable to craete kmem cache\n");
		return NULL;
	}

	virtmem_pool = mempool_create_slab_pool(64, ppa_cache);
	if (!virtmem_pool) {
		pr_err("null_nvm: Unable to create virtual memory pool\n");
		return NULL;
	}

	return virtmem_pool;
}

static void null_destroy_ppa_pool(void *pool)
{
	mempool_t *virtmem_pool = pool;

	mempool_destroy(virtmem_pool);
}

static void *null_alloc_ppalist(struct request_queue *q, void *pool,
				gfp_t mem_flags, dma_addr_t *dma_handler)
{

	struct sector_t *ppa_list;
	mempool_t *virtmem_pool = pool;

	ppa_list = mempool_alloc(virtmem_pool, mem_flags);
	if (!ppa_list) {
		pr_err("null_nvm: Unable to allocate virtual memory\n");
		return NULL;
	}

	return ppa_list;
}

static void null_free_ppalist(void *pool, void *ppa_list,
							dma_addr_t dma_handler)
{
	mempool_t *virtmem_pool = pool;

	mempool_free(ppa_list, virtmem_pool);
}

static struct nvm_dev_ops nulln_dev_ops = {
	.identify	= null_id,

	.get_features		= null_get_features,

	.submit_io		= null_submit_io,

	.create_ppa_pool	= null_create_ppa_pool,
	.destroy_ppa_pool	= null_destroy_ppa_pool,
	.alloc_ppalist		= null_alloc_ppalist,
	.free_ppalist		= null_free_ppalist,

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
		struct completion_queue *cq = &per_cpu(completion_queues, i);

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
