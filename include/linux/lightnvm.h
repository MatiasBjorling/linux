#ifndef NVM_H
#define NVM_H

enum {
	NVM_PREP_OK = 0,
	NVM_PREP_BUSY = 1,
	NVM_PREP_REQUEUE = 2,
	NVM_PREP_DONE = 3,
	NVM_PREP_ERROR = 4,

	NVM_IOTYPE_NONE = 0,
	NVM_IOTYPE_GC = 1,
};

#ifdef CONFIG_NVM

#include <linux/blkdev.h>
#include <linux/types.h>
#include <linux/file.h>

enum {
	/* HW Responsibilities */
	NVM_RSP_L2P	= 1 << 0,
	NVM_RSP_GC	= 1 << 1,
	NVM_RSP_ECC	= 1 << 2,

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

struct nvm_target_instance {
	struct nvm_target_type *tt;
};

struct nvm_rq {
	struct nvm_target_instance *ins;
	sector_t phys_sector;
};

static inline struct nvm_rq *nvm_rq_from_pdu(void *pdu)
{
	return pdu - sizeof(struct nvm_rq);
}

static inline void *nvm_rq_to_pdu(struct nvm_rq *rqdata)
{
	return rqdata + 1;
}

struct nvm_block;

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
typedef int (nvm_submit_io_fn)(struct request_queue *, struct bio *,
				struct nvm_rq *, struct nvm_target_instance *);
typedef int (nvm_erase_blk_fn)(struct request_queue *, sector_t);

struct nvm_dev_ops {
	nvm_id_fn		*identify;
	nvm_get_features_fn	*get_features;
	nvm_set_rsp_fn		*set_responsibility;
	nvm_get_l2p_tbl_fn	*get_l2p_tbl;
	nvm_op_bb_tbl_fn	*set_bb_tbl;
	nvm_op_bb_tbl_fn	*get_bb_tbl;

	nvm_submit_io_fn	*submit_io;
	nvm_erase_blk_fn	*erase_block;
};

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

	struct list_head online_targets;

	struct nvm_bm_type *bm;
	void *bmp;

	int nr_luns;

	/* Calculated/Cached values. These do not reflect the actual usable
	 * blocks at run-time. */
	unsigned long total_pages;
	unsigned long total_blocks;
	unsigned max_pages_per_blk;

	uint32_t sector_size;

	struct nvm_id identity;
	struct nvm_get_features features;
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

typedef void (nvm_tgt_make_rq)(struct request_queue *, struct bio *);
typedef sector_t (nvm_tgt_capacity)(void *);
typedef void *(nvm_tgt_init_fn)(struct gendisk *, struct gendisk *, int, int);
typedef void (nvm_tgt_exit_fn)(void *);

struct nvm_target_type {
	const char *name;
	unsigned int version[3];

	/* target entry points */
	nvm_tgt_make_rq *make_rq;
	nvm_tgt_capacity *capacity;

	/* module-specific init/teardown */
	nvm_tgt_init_fn *init;
	nvm_tgt_exit_fn *exit;

	/* For internal use */
	struct list_head list;
};

extern int nvm_register_target(struct nvm_target_type *);
extern void nvm_unregister_target(struct nvm_target_type *);

typedef int (nvm_bm_register_fn)(struct nvm_dev *);
typedef void (nvm_bm_unregister_fn)(struct nvm_dev *);
typedef struct nvm_block *(nvm_bm_get_blk_fn)(struct nvm_dev *,
					      struct nvm_lun *, unsigned long);
typedef void (nvm_bm_put_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvm_bm_open_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvm_bm_close_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef void (nvm_bm_flush_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvm_bm_submit_io_fn)(struct nvm_dev *, struct bio *,
	     struct nvm_rq *, struct nvm_target_instance *);
typedef int (nvm_bm_erase_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvm_bm_register_prog_err_fn)(struct nvm_dev *,
	     void (prog_err_fn)(struct nvm_dev *, struct nvm_block *));
typedef int (nvm_bm_save_state_fn)(struct file *);
typedef int (nvm_bm_restore_state_fn)(struct file *);
typedef struct nvm_lun *(nvm_bm_get_luns_fn)(struct nvm_dev *, int, int);
typedef void (nvm_bm_free_blocks_print_fn)(struct nvm_dev *, char *);

struct nvm_bm_type {
	const char *name;
	unsigned int version[3];

	nvm_bm_register_fn *register_bm;
	nvm_bm_unregister_fn *unregister_bm;

	/* Block administration callbacks */
	nvm_bm_get_blk_fn *get_blk;
	nvm_bm_put_blk_fn *put_blk;
	nvm_bm_open_blk_fn *open_blk;
	nvm_bm_close_blk_fn *close_blk;
	nvm_bm_flush_blk_fn *flush_blk;

	nvm_bm_submit_io_fn *submit_io;
	nvm_bm_erase_blk_fn *erase_blk;

	/* State management for debugging purposes */
	nvm_bm_save_state_fn *save_state;
	nvm_bm_restore_state_fn *restore_state;

	/* Configuration management */
	nvm_bm_get_luns_fn *get_luns;

	/* Statistics */
	nvm_bm_free_blocks_print_fn *free_blocks_print;
	struct list_head list;
};

extern int nvm_register_bm(struct nvm_bm_type *);
extern void nvm_unregister_bm(struct nvm_bm_type *);

extern struct nvm_block *nvm_get_blk(struct nvm_dev *, struct nvm_lun *,
								unsigned long);
extern void nvm_put_blk(struct nvm_dev *, struct nvm_block *);
extern int nvm_erase_blk(struct nvm_dev *, struct nvm_block *);

extern int nvm_register(struct request_queue *, struct gendisk *,
							struct nvm_dev_ops *);
extern void nvm_unregister(struct gendisk *);

extern int nvm_submit_io(struct nvm_dev *, struct bio *, struct nvm_rq *rqdata,
			struct nvm_target_instance *);
extern int nvm_prep_rq(struct request *, struct nvm_rq *);
extern void nvm_unprep_rq(struct request *, struct nvm_rq *);

extern sector_t nvm_alloc_addr(struct nvm_block *);
static inline struct nvm_dev *nvm_get_dev(struct gendisk *disk)
{
	return disk->nvm;
}

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

static inline unsigned long nvm_get_rq_flags(struct request *rq)
{
	return (unsigned long)rq->cmd;
}

static inline void nvm_init_rq_data(struct nvm_rq *rqdata)
{
	rqdata->phys_sector = 0;
}

#else /* CONFIG_NVM */

struct nvm_dev_ops;
struct nvm_dev;
struct nvm_lun;
struct nvm_block;
struct nvm_rq {
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
static inline int nvm_prep_rq(struct request *rq, struct nvm_rq *rqdata)
{
	return -EINVAL;
}
static inline void nvm_unprep_rq(struct request *rq, struct nvm_rq *rqdata)
{
}
static inline struct nvm_block *nvm_get_blk(struct nvm_dev *dev,
				struct nvm_lun *lun, unsigned long flags)
{
	return NULL;
}
static inline void nvm_put_blk(struct nvm_dev *dev, struct nvm_block *blk) {}
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
static inline void nvm_init_rq_data(struct nvm_rq *rqdata) { }
static inline int nvm_attach_sysfs(struct gendisk *dev) { return 0; }


#endif /* CONFIG_NVM */
#endif /* LIGHTNVM.H */
