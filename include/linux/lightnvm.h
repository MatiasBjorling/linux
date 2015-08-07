#ifndef NVM_H
#define NVM_H

enum {
	NVM_IO_OK = 0,
	NVM_IO_REQUEUE = 1,
	NVM_IO_DONE = 2,
	NVM_IO_ERR = 3,

	NVM_IOTYPE_NONE = 0,
	NVM_IOTYPE_GC = 1,
};

#ifdef CONFIG_NVM

#include <linux/blkdev.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/dmapool.h>

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
	struct nvm_tgt_type *type;
	struct gendisk *disk;
};

struct nvm_tgt_instance {
	struct nvm_tgt_type *tt;
};

struct nvm_rq {
	struct nvm_tgt_instance *ins;
	struct bio *bio;
	union {
		sector_t ppa;
		sector_t *ppa_list;
	};
	/*DMA handler to be used by underlying devices supporting DMA*/
	dma_addr_t dma_ppa_list;
	uint8_t npages;
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
typedef int (nvm_submit_io_fn)(struct request_queue *, struct nvm_rq *);
typedef int (nvm_erase_blk_fn)(struct request_queue *, sector_t);
typedef void *(nvm_create_ppapool_fn)(struct request_queue *);
typedef void (nvm_destroy_ppapool_fn)(void *);
typedef void *(nvm_alloc_ppalist_fn)(struct request_queue *, void *, gfp_t,
								dma_addr_t*);
typedef void (nvm_free_ppalist_fn)(void *, void*, dma_addr_t);

struct nvm_dev_ops {
	nvm_id_fn		*identify;
	nvm_get_features_fn	*get_features;
	nvm_set_rsp_fn		*set_responsibility;
	nvm_get_l2p_tbl_fn	*get_l2p_tbl;
	nvm_op_bb_tbl_fn	*set_bb_tbl;
	nvm_op_bb_tbl_fn	*get_bb_tbl;

	nvm_submit_io_fn	*submit_io;
	nvm_erase_blk_fn	*erase_block;

	nvm_create_ppapool_fn	*create_ppa_pool;
	nvm_destroy_ppapool_fn	*destroy_ppa_pool;
	nvm_alloc_ppalist_fn	*alloc_ppalist;
	nvm_free_ppalist_fn	*free_ppalist;

	int			dev_sector_size;
	uint8_t			max_phys_sect;
};

struct nvm_lun {
	int id;

	int nr_pages_per_blk;
	unsigned int nr_blocks;		/* end_block - start_block. */
	unsigned int nr_free_blocks;	/* Number of unused blocks */

	struct nvm_block *blocks;

	spinlock_t lock;
};

struct nvm_block {
	struct list_head list;
	struct nvm_lun *lun;
	unsigned long long id;

	void *priv;
	int type;
};

struct nvm_dev {
	struct nvm_dev_ops *ops;

	struct list_head devices;
	struct list_head online_targets;

	/* Block manager */
	struct nvm_bm_type *bm;
	void *bmp;

	/* Target information */
	int nr_luns;

	/* Calculated/Cached values. These do not reflect the actual usable
	 * blocks at run-time. */
	unsigned long total_pages;
	unsigned long total_blocks;
	unsigned max_pages_per_blk;

	uint32_t sector_size;

	void *ppalist_pool;

	/* Identity */
	struct nvm_id identity;
	struct nvm_get_features features;

	/* Backend device */
	struct request_queue *q;
	char name[DISK_NAME_LEN];
};

typedef void (nvm_tgt_make_rq_fn)(struct request_queue *, struct bio *);
typedef sector_t (nvm_tgt_capacity_fn)(void *);
typedef void (nvm_tgt_end_io_fn)(struct nvm_rq *, int);
typedef void *(nvm_tgt_init_fn)(struct nvm_dev *, struct gendisk *, int, int);
typedef void (nvm_tgt_exit_fn)(void *);

struct nvm_tgt_type {
	const char *name;
	unsigned int version[3];

	/* target entry points */
	nvm_tgt_make_rq_fn *make_rq;
	nvm_tgt_capacity_fn *capacity;
	nvm_tgt_end_io_fn *end_io;

	/* module-specific init/teardown */
	nvm_tgt_init_fn *init;
	nvm_tgt_exit_fn *exit;

	/* For internal use */
	struct list_head list;
};

extern int nvm_register_target(struct nvm_tgt_type *);
extern void nvm_unregister_target(struct nvm_tgt_type *);

extern void *nvm_alloc_ppalist(struct nvm_dev *, gfp_t, dma_addr_t *);
extern void nvm_free_ppalist(struct nvm_dev *, void *, dma_addr_t);

typedef int (nvm_bm_register_fn)(struct nvm_dev *);
typedef void (nvm_bm_unregister_fn)(struct nvm_dev *);
typedef struct nvm_block *(nvm_bm_get_blk_fn)(struct nvm_dev *,
					      struct nvm_lun *, unsigned long);
typedef void (nvm_bm_put_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvm_bm_open_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvm_bm_close_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef void (nvm_bm_flush_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvm_bm_submit_io_fn)(struct nvm_dev *, struct nvm_rq *);
typedef void (nvm_bm_end_io_fn)(struct nvm_rq *, int);
typedef int (nvm_bm_erase_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvm_bm_register_prog_err_fn)(struct nvm_dev *,
	     void (prog_err_fn)(struct nvm_dev *, struct nvm_block *));
typedef int (nvm_bm_save_state_fn)(struct file *);
typedef int (nvm_bm_restore_state_fn)(struct file *);
typedef struct nvm_lun *(nvm_bm_get_luns_fn)(struct nvm_dev *, int, int);
typedef void (nvm_bm_free_blocks_print_fn)(struct nvm_dev *);

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
	nvm_bm_end_io_fn *end_io;
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

extern int nvm_register(struct request_queue *, char *,
						struct nvm_dev_ops *);
extern void nvm_unregister(char *);

extern int nvm_submit_io(struct nvm_dev *, struct nvm_rq *);

/* We currently assume that we the lightnvm device is accepting data in 512
 * bytes chunks. This should be set to the smallest command size available for a
 * given device.
 */

#define DEV_EXPOSED_PAGE_SIZE (4096)

#define NVM_MSG_PREFIX "nvm"
#define ADDR_EMPTY (~0ULL)

static inline unsigned long nvm_get_rq_flags(struct request *rq)
{
	return (unsigned long)rq->cmd;
}

#else /* CONFIG_NVM */

struct nvm_dev_ops;
struct nvm_dev;
struct nvm_lun;
struct nvm_block;
struct nvm_rq {
};
struct nvm_tgt_type;
struct nvm_tgt_instance;

static inline struct nvm_tgt_type *nvm_find_target_type(const char *c)
{
	return NULL;
}
static inline int nvm_register(struct request_queue *q, char *disk_name,
							struct nvm_dev_ops *ops)
{
	return -EINVAL;
}
static inline void nvm_unregister(char *disk_name) {}
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

#endif /* CONFIG_NVM */
#endif /* LIGHTNVM.H */
