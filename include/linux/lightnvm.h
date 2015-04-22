#ifndef NVM_H
#define NVM_H

enum {
	NVM_PREP_OK = 0,
	NVM_PREP_BUSY = 1,
	NVM_PREP_REQUEUE = 2,
	NVM_PREP_DONE = 3,
	NVM_PREP_ERROR = 4,
};

#ifdef CONFIG_NVM

#include <linux/blkdev.h>
#include <linux/types.h>

enum {
	/* HW Responsibilities */
	NVM_RSP_L2P	= 0x00,
	NVM_RSP_GC	= 0x01,
	NVM_RSP_ECC	= 0x02,

	/* Physical NVM Type */
	NVM_NVMT_BLK	= 0,
	NVM_NVMT_BYTE	= 1,

	/* Internal IO Scheduling algorithm */
	NVM_IOSCHED_CHANNEL	= 0,
	NVM_IOSCHED_CHIP	= 1,

	/* Status codes */
	NVM_SUCCESS		= 0,
	NVM_RSP_NOT_CHANGEABLE	= 1,
};

struct nvm_id_chnl {
	u64	laddr_begin;
	u64	laddr_end;
	u32	oob_size;
	u32	queue_size;
	u32	gran_read;
	u32	gran_write;
	u32	gran_erase;
	u32	t_r;
	u32	t_sqr;
	u32	t_w;
	u32	t_sqw;
	u32	t_e;
	u16	chnl_parallelism;
	u8	io_sched;
	u8	res[133];
};

struct nvm_id {
	u8	ver_id;
	u8	nvm_type;
	u16	nchannels;
	struct nvm_id_chnl *chnls;
};

struct nvm_get_features {
	u64	rsp;
	u64	ext;
};

struct nvm_target {
	struct list_head list;
	struct nvm_target_type *type;
	struct gendisk *disk;
};

struct nvm_internal_cmd {
	void *target;
	sector_t phys_lba;
	int rw;
	void *buffer;
	unsigned bufflen;
	unsigned timeout;
};

extern void nvm_unregister(struct gendisk *);
extern int nvm_attach_sysfs(struct gendisk *disk);

typedef int (nvm_l2p_update_fn)(u64, u64, u64 *, void *);
typedef int (nvm_bb_update_fn)(u32, void *, unsigned int, void *);
typedef int (nvm_id_fn)(struct request_queue *, struct nvm_id *);
typedef int (nvm_get_features_fn)(struct request_queue *,
						struct nvm_get_features *);
typedef int (nvm_set_rsp_fn)(struct request_queue *, u64);
typedef int (nvm_get_l2p_tbl_fn)(struct request_queue *, u64, u64,
				nvm_l2p_update_fn *, void *);
typedef int (nvm_op_bb_tbl_fn)(struct request_queue *, int, unsigned int,
				nvm_bb_update_fn *, void *);
typedef int (nvm_internal_rw_fn)(struct request_queue *,
						struct nvm_internal_cmd *);
typedef int (nvm_erase_blk_fn)(struct request_queue *, sector_t);

struct nvm_dev_ops {
	nvm_id_fn		*identify;
	nvm_get_features_fn	*get_features;
	nvm_set_rsp_fn		*set_responsibility;
	nvm_get_l2p_tbl_fn	*get_l2p_tbl;
	nvm_op_bb_tbl_fn	*set_bb_tbl;
	nvm_op_bb_tbl_fn	*get_bb_tbl;

	nvm_internal_rw_fn	*internal_rw;
	nvm_erase_blk_fn	*erase_block;
};

struct nvm_blocks;

/*
 * We assume that the device exposes its channels as a linear address
 * space. A lun therefore have a phy_addr_start and phy_addr_end that
 * denotes the start and end. This abstraction is used to let the
 * open-channel SSD (or any other device) expose its read/write/erase
 * interface and be administrated by the host system.
 */
struct nvm_lun {
	struct nvm_dev *dev;

	/* lun block lists */
	struct list_head used_list;	/* In-use blocks */
	struct list_head free_list;	/* Not used blocks i.e. released
					 * and ready for use */
	struct list_head bb_list;	/* Bad blocks. Mutually exclusive with
					   free_list and used_list */


	struct {
		spinlock_t lock;
	} ____cacheline_aligned_in_smp;

	struct nvm_block *blocks;
	struct nvm_id_chnl *chnl;

	int id;
	int reserved_blocks;

	unsigned int nr_blocks;		/* end_block - start_block. */
	unsigned int nr_free_blocks;	/* Number of unused blocks */

	int nr_pages_per_blk;
};

struct nvm_block {
	/* Management structures */
	struct list_head list;
	struct nvm_lun *lun;

	spinlock_t lock;

#define MAX_INVALID_PAGES_STORAGE 8
	/* Bitmap for invalid page intries */
	unsigned long invalid_pages[MAX_INVALID_PAGES_STORAGE];
	/* points to the next writable page within a block */
	unsigned int next_page;
	/* number of pages that are invalid, wrt host page size */
	unsigned int nr_invalid_pages;

	unsigned int id;
	int type;
	/* Persistent data structures */
	atomic_t data_cmnt_size; /* data pages committed to stable storage */
};

struct nvm_dev {
	struct nvm_dev_ops *ops;
	struct request_queue *q;

	struct nvm_id identity;

	struct list_head online_targets;

	int nr_luns;
	struct nvm_lun *luns;

	/*int nr_blks_per_lun;
	int nr_pages_per_blk;*/
	/* Calculated/Cached values. These do not reflect the actual usuable
	 * blocks at run-time. */
	unsigned long total_pages;
	unsigned long total_blocks;

	uint32_t sector_size;
};

struct nvm_rq_data {
		sector_t phys_sector;
};

/* Logical to physical mapping */
struct nvm_addr {
	sector_t addr;
	struct nvm_block *block;
};

/* Physical to logical mapping */
struct nvm_rev_addr {
	sector_t addr;
};

struct rrpc_inflight_rq {
	struct list_head list;
	sector_t l_start;
	sector_t l_end;
};

struct nvm_per_rq {
	struct rrpc_inflight_rq inflight_rq;
	struct nvm_addr *addr;
	unsigned int flags;
};

typedef void (nvm_tgt_make_rq)(struct request_queue *, struct bio *);
typedef int (nvm_tgt_prep_rq)(struct request *, struct nvm_rq_data *, void *);
typedef void (nvm_tgt_unprep_rq)(struct request *, struct nvm_rq_data *,
									void *);
typedef sector_t (nvm_tgt_capacity)(void *);
typedef void *(nvm_tgt_init_fn)(struct gendisk *, struct gendisk *, int, int);
typedef void (nvm_tgt_exit_fn)(void *);

struct nvm_target_type {
	const char *name;
	unsigned int version[3];

	/* target entry points */
	nvm_tgt_make_rq *make_rq;
	nvm_tgt_prep_rq *prep_rq;
	nvm_tgt_unprep_rq *unprep_rq;
	nvm_tgt_capacity *capacity;

	/* module-specific init/teardown */
	nvm_tgt_init_fn *init;
	nvm_tgt_exit_fn *exit;

	/* For open-channel SSD internal use */
	struct list_head list;
};

struct nvm_target_instance {
	struct bio_nvm_payload payload;
	struct nvm_target_type *tt;
};

extern struct nvm_target_type *nvm_find_target_type(const char *);
extern int nvm_register_target(struct nvm_target_type *);
extern void nvm_unregister_target(struct nvm_target_type *);
extern int nvm_register(struct request_queue *, struct gendisk *,
							struct nvm_dev_ops *);
extern void nvm_unregister(struct gendisk *);
extern int nvm_prep_rq(struct request *, struct nvm_rq_data *);
extern void nvm_unprep_rq(struct request *, struct nvm_rq_data *);
extern struct nvm_block *nvm_get_blk(struct nvm_lun *, int);
extern void nvm_put_blk(struct nvm_block *block);
extern int nvm_internal_rw(struct nvm_dev *, struct nvm_internal_cmd *);
extern int nvm_erase_blk(struct nvm_dev *, struct nvm_block *);
extern sector_t nvm_alloc_addr(struct nvm_block *);
static inline struct nvm_dev *nvm_get_dev(struct gendisk *disk)
{
	return disk->nvm;
}

#define nvm_for_each_lun(dev, lun, i) \
		for ((i) = 0, lun = &(dev)->luns[0]; \
			(i) < (dev)->nr_luns; (i)++, lun = &(dev)->luns[(i)])

#define lun_for_each_block(p, b, i) \
		for ((i) = 0, b = &(p)->blocks[0]; \
			(i) < (p)->nr_blocks; (i)++, b = &(p)->blocks[(i)])

#define block_for_each_page(b, p) \
		for ((p)->addr = block_to_addr((b)), (p)->block = (b); \
			(p)->addr < block_to_addr((b)) \
				+ (b)->lun->dev->nr_pages_per_blk; \
			(p)->addr++)

/* We currently assume that we the lightnvm device is accepting data in 512
 * bytes chunks. This should be set to the smallest command size available for a
 * given device.
 */
#define NVM_SECTOR (512)
#define EXPOSED_PAGE_SIZE (4096)

#define NR_PHY_IN_LOG (EXPOSED_PAGE_SIZE / NVM_SECTOR)

#define NVM_MSG_PREFIX "nvm"
#define ADDR_EMPTY (~0ULL)

static inline int block_is_full(struct nvm_block *block)
{
	struct nvm_lun *lun = block->lun;

	return block->next_page == lun->nr_pages_per_blk;
}

static inline sector_t block_to_addr(struct nvm_block *block)
{
	struct nvm_lun *lun = block->lun;

	return block->id * lun->nr_pages_per_blk;
}

static inline struct nvm_lun *paddr_to_lun(struct nvm_dev *dev,
							sector_t p_addr)
{
	return &dev->luns[p_addr / (dev->total_pages / dev->nr_luns)];
}

static inline void nvm_init_rq_data(struct nvm_rq_data *rqdata)
{
	rqdata->phys_sector = 0;
}

#else /* CONFIG_NVM */

struct nvm_dev_ops;
struct nvm_dev;
struct nvm_lun;
struct nvm_block;
struct nvm_per_rq {
};
struct nvm_rq_data {
};
struct nvm_internal_cmd {
};
struct nvm_target_type;
struct nvm_target_instance;

static inline struct nvm_target_type *nvm_find_target_type(const char *c)
{
	return NULL;
}
static inline int nvm_register_target(struct nvm_target_type *tt)
{
	return -EINVAL;
}
static inline void nvm_unregister_target(struct nvm_target_type *tt) {}
static inline int nvm_register(struct request_queue *q, struct gendisk *disk,
							struct nvm_dev_ops *ops)
{
	return -EINVAL;
}
static inline void nvm_unregister(struct gendisk *disk) {}
static inline int nvm_prep_rq(struct request *rq, struct nvm_rq_data *rqdata)
{
	return -EINVAL;
}
static inline void nvm_unprep_rq(struct request *rq, struct nvm_rq_data *rqdata)
{
}
static inline struct nvm_block *nvm_get_blk(struct nvm_lun *lun, int is_gc)
{
	return NULL;
}
static inline void nvm_put_blk(struct nvm_block *blk) {}
static inline int nvm_internal_rw(struct nvm_dev *dev,
					const struct nvm_internal_cmd *cmd)
{
	return -EINVAL;
}
static inline int nvm_erase_blk(struct nvm_dev *dev, struct nvm_block *blk)
{
	return -EINVAL;
}
static inline sector_t nvm_alloc_addr(struct nvm_block *blk)
{
	return 0;
}
static inline struct nvm_dev *nvm_get_dev(struct gendisk *disk)
{
	return NULL;
}
static inline void nvm_init_rq_data(struct nvm_rq_data *rqdata) { }
static inline int nvm_attach_sysfs(struct gendisk *dev) { return 0; }


#endif /* CONFIG_NVM */
#endif /* LIGHTNVM.H */
