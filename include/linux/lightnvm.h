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

	/* Physical Adressing Mode */
	NVM_ADDRMODE_LINEAR	= 0,
	NVM_ADDRMODE_CHANNEL	= 1,

	/* Plane programming mode for LUN */
	NVM_PLANE_SINGLE	= 0,
	NVM_PLANE_DOUBLE	= 1,
	NVM_PLANE_QUAD		= 2,

	/* Status codes */
	NVM_RSP_SUCCESS		= 0x0,
	NVM_RSP_NOT_CHANGEABLE	= 0x1,
	NVM_RSP_ERR_FAILWRITE	= 0x40ff,

	/* Device opcodes */
	NVM_OP_HBREAD		= 0x20,
	NVM_OP_HBWRITE		= 0x21,
	NVM_OP_PREAD		= 0x22,
	NVM_OP_PWRITE		= 0x23,
	NVM_OP_ERASE		= 0x30,
};

struct nvm_id_group {
	u64	laddr_begin;
	u32	queue_size;
	u32	channels;
	u32	luns_per_chnl;
	u32	sec_per_pg;
	u32	pgs_per_blk;
	u32	blks;
	u32	planes;
	u32	sec_size;
	u32	oob_size;
	u32	t_r;
	u32	t_sqr;
	u32	t_w;
	u32	t_sqw;
	u32	t_e;
	u16	chnl_parallelism;
	u8	plane_mode;
	u8	addr_mode;
	u8	res[124];
} __packed;

struct nvm_id {
	u16	ver_id;
	u16	ngroups;
	u16	nvm_vendor;
	u8	resv[250];
	struct nvm_id_group groups[20];
} __packed;

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

/* The minimum managed sector size is currently 4K. */
#define DEV_EXPOSED_PAGE_SIZE (4096)

#define NVM_MSG_PREFIX "nvm"
#define ADDR_EMPTY (~0ULL)

#define NVM_VERSION_MAJOR 1
#define NVM_VERSION_MINOR 0
#define NVM_VERSION_PATCH 0


#define NVM_SEC_BITS (8)
#define NVM_PL_BITS  (6)
#define NVM_PG_BITS  (16)
#define NVM_BLK_BITS (16)
#define NVM_LUN_BITS (10)
#define NVM_CH_BITS  (8)

struct ppa_addr {
	union {
		/* Channel-based PPA format in nand 4x2x2x2x8x10 */
		struct {
			sector_t ch		: 4;
			sector_t sec		: 2; /* 4 sectors per page */
			sector_t pl		: 2; /* 4 planes per LUN */
			sector_t lun		: 2; /* 4 LUNs per channel */
			sector_t pg		: 8; /* 256 pages per block */
			sector_t blk		: 10;/* 1024 blocks per plane */
			sector_t resved		: 36;
		} chnl;

		/* Generic structure for all addresses */
		struct {
			sector_t sec		: NVM_SEC_BITS;
			sector_t pl		: NVM_PL_BITS;
			sector_t pg		: NVM_PG_BITS;
			sector_t blk		: NVM_BLK_BITS;
			sector_t lun		: NVM_LUN_BITS;
			sector_t ch		: NVM_CH_BITS;
		} g;

		sector_t ppa;
	};
} __packed;

struct nvm_rq {
	struct nvm_tgt_instance *ins;
	struct nvm_dev *dev;

	struct bio *bio;

	union {
		struct ppa_addr ppa_addr;
		struct ppa_addr *ppa_list;
	};

	/*DMA handler to be used by underlying devices supporting DMA*/
	dma_addr_t dma_ppa_list;

	void *metadata;
	dma_addr_t dma_metadata;

	unsigned short opcode;
	unsigned char nr_pages;
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
typedef int (nvm_op_set_bb_fn)(struct request_queue *, struct nvm_rq *, int);
typedef int (nvm_submit_io_fn)(struct request_queue *, struct nvm_rq *);
typedef int (nvm_erase_blk_fn)(struct request_queue *, struct nvm_rq *);
typedef void *(nvm_create_dma_pool_fn)(struct request_queue *, char *);
typedef void (nvm_destroy_dma_pool_fn)(void *);
typedef void *(nvm_dev_dma_alloc_fn)(struct request_queue *, void *, gfp_t,
								dma_addr_t*);
typedef void (nvm_dev_dma_free_fn)(void *, void*, dma_addr_t);

struct nvm_dev_ops {
	nvm_id_fn		*identify;
	nvm_get_features_fn	*get_features;
	nvm_set_rsp_fn		*set_responsibility;
	nvm_get_l2p_tbl_fn	*get_l2p_tbl;
	nvm_op_bb_tbl_fn	*get_bb_tbl;
	nvm_op_set_bb_fn	*set_bb;

	nvm_submit_io_fn	*submit_io;
	nvm_erase_blk_fn	*erase_block;

	nvm_create_dma_pool_fn	*create_dma_pool;
	nvm_destroy_dma_pool_fn	*destroy_dma_pool;
	nvm_dev_dma_alloc_fn	*dev_dma_alloc;
	nvm_dev_dma_free_fn	*dev_dma_free;

	int			dev_sector_size;
	uint8_t			max_phys_sect;
};

struct nvm_lun {
	int id;

	int lun_id;
	int chnl_id;

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

	/* Media manager */
	struct nvmm_type *mt;
	void *mp;

	/* Device information */
	int nr_chnls;
	int nr_planes;
	int luns_per_chnl;
	int sec_per_pg; /* only sectors for a single page */
	int pgs_per_blk;
	int blks_per_lun;
	int sec_size;
	int oob_size;
	int addr_mode;
	int plane_mode;

	/* Calculated/Cached values. These do not reflect the actual usable
	 * blocks at run-time.
	 */

	int sec_per_pl; /* all sectors across planes */
	int sec_per_blk;
	int sec_per_lun;

	unsigned long total_pages;
	unsigned long total_blocks;
	int nr_luns;
	unsigned max_pages_per_blk;

	void *ppalist_pool;

	/* Identity */
	struct nvm_id identity;
	struct nvm_get_features features;

	/* Backend device */
	struct request_queue *q;
	char name[DISK_NAME_LEN];
};

/* fallback conversion */
static struct ppa_addr __generic_to_linear_addr(struct nvm_dev *dev,
							struct ppa_addr r)
{
	struct ppa_addr l;

	l.ppa = r.g.sec +
		r.g.pg  * dev->sec_per_pg +
		r.g.blk * (dev->pgs_per_blk *
				dev->sec_per_pg) +
		r.g.lun * (dev->blks_per_lun *
				dev->pgs_per_blk *
				dev->sec_per_pg) +
		r.g.ch * (dev->blks_per_lun *
				dev->pgs_per_blk *
				dev->luns_per_chnl *
				dev->sec_per_pg);

	return l;
}

/* fallback conversion */
static struct ppa_addr __linear_to_generic_addr(struct nvm_dev *dev,
							struct ppa_addr r)
{
	struct ppa_addr l;

	l.ppa = 0;

	l.g.sec = r.ppa % dev->sec_per_pg;
	l.g.pg = (r.ppa / dev->sec_per_pg) % dev->pgs_per_blk;
	l.g.blk = (r.ppa / (dev->pgs_per_blk *
				dev->sec_per_pg)) % dev->blks_per_lun;
	l.g.lun = (r.ppa / (dev->blks_per_lun *
				dev->pgs_per_blk *
				dev->sec_per_pg)) % dev->luns_per_chnl;
	l.g.ch = r.ppa / (dev->blks_per_lun *
				dev->pgs_per_blk *
				dev->luns_per_chnl *
				dev->sec_per_pg);

	return l;
}

static struct ppa_addr __generic_to_chnl_addr(struct ppa_addr r)
{
	struct ppa_addr l;

	l.ppa = 0;

	l.chnl.sec = r.g.sec;
	l.chnl.pl = r.g.pl;
	l.chnl.pg = r.g.pg;
	l.chnl.blk = r.g.blk;
	l.chnl.lun = r.g.lun;
	l.chnl.ch = r.g.ch;

	return l;
}

static struct ppa_addr __chnl_to_generic_addr(struct ppa_addr r)
{
	struct ppa_addr l;

	l.ppa = 0;

	l.g.sec = r.chnl.sec;
	l.g.pl = r.chnl.pl;
	l.g.pg = r.chnl.pg;
	l.g.blk = r.chnl.blk;
	l.g.lun = r.chnl.lun;
	l.g.ch = r.chnl.ch;

	return l;
}

static inline struct ppa_addr addr_to_generic_mode(struct nvm_dev *dev,
						struct ppa_addr gppa)
{
	switch (dev->addr_mode) {
	case NVM_ADDRMODE_LINEAR:
		return __linear_to_generic_addr(dev, gppa);
	case NVM_ADDRMODE_CHANNEL:
		return __chnl_to_generic_addr(gppa);
	default:
		BUG();
	}
	return gppa;
}

static inline struct ppa_addr generic_to_addr_mode(struct nvm_dev *dev,
						struct ppa_addr gppa)
{
	switch (dev->addr_mode) {
	case NVM_ADDRMODE_LINEAR:
		return __generic_to_linear_addr(dev, gppa);
	case NVM_ADDRMODE_CHANNEL:
		return __generic_to_chnl_addr(gppa);
	default:
		BUG();
	}
	return gppa;
}

static inline int ppa_empty(struct ppa_addr ppa_addr)
{
	return (ppa_addr.ppa == ADDR_EMPTY);
}

static inline void ppa_set_empty(struct ppa_addr *ppa_addr)
{
	ppa_addr->ppa = ADDR_EMPTY;
}

static inline struct ppa_addr block_to_ppa(struct nvm_dev *dev,
							struct nvm_block *blk)
{
	struct ppa_addr ppa;
	struct nvm_lun *lun = blk->lun;

	ppa.ppa = 0;
	ppa.g.blk = blk->id % dev->blks_per_lun;
	ppa.g.lun = lun->lun_id;
	ppa.g.ch = lun->chnl_id;

	return ppa;
}

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

extern void *nvm_dev_dma_alloc(struct nvm_dev *, gfp_t, dma_addr_t *);
extern void nvm_dev_dma_free(struct nvm_dev *, void *, dma_addr_t);

typedef int (nvmm_register_fn)(struct nvm_dev *);
typedef void (nvmm_unregister_fn)(struct nvm_dev *);
typedef struct nvm_block *(nvmm_get_blk_fn)(struct nvm_dev *,
					      struct nvm_lun *, unsigned long);
typedef void (nvmm_put_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvmm_open_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvmm_close_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef void (nvmm_flush_blk_fn)(struct nvm_dev *, struct nvm_block *);
typedef int (nvmm_submit_io_fn)(struct nvm_dev *, struct nvm_rq *);
typedef void (nvmm_end_io_fn)(struct nvm_rq *, int);
typedef int (nvmm_erase_blk_fn)(struct nvm_dev *, struct nvm_block *,
								unsigned long);
typedef int (nvmm_register_prog_err_fn)(struct nvm_dev *,
	     void (prog_err_fn)(struct nvm_dev *, struct nvm_block *));
typedef int (nvmm_save_state_fn)(struct file *);
typedef int (nvmm_restore_state_fn)(struct file *);
typedef struct nvm_lun *(nvmm_get_lun_fn)(struct nvm_dev *, int);
typedef void (nvmm_free_blocks_print_fn)(struct nvm_dev *);

struct nvmm_type {
	const char *name;
	unsigned int version[3];

	nvmm_register_fn *register_mgr;
	nvmm_unregister_fn *unregister_mgr;

	/* Block administration callbacks */
	nvmm_get_blk_fn *get_blk;
	nvmm_put_blk_fn *put_blk;
	nvmm_open_blk_fn *open_blk;
	nvmm_close_blk_fn *close_blk;
	nvmm_flush_blk_fn *flush_blk;

	nvmm_submit_io_fn *submit_io;
	nvmm_end_io_fn *end_io;
	nvmm_erase_blk_fn *erase_blk;

	/* State management for debugging purposes */
	nvmm_save_state_fn *save_state;
	nvmm_restore_state_fn *restore_state;

	/* Configuration management */
	nvmm_get_lun_fn *get_lun;

	/* Statistics */
	nvmm_free_blocks_print_fn *free_blocks_print;
	struct list_head list;
};

extern int nvm_register_mgr(struct nvmm_type *);
extern void nvm_unregister_mgr(struct nvmm_type *);

extern struct nvm_block *nvm_get_blk(struct nvm_dev *, struct nvm_lun *,
								unsigned long);
extern void nvm_put_blk(struct nvm_dev *, struct nvm_block *);

extern int nvm_register(struct request_queue *, char *,
						struct nvm_dev_ops *);
extern void nvm_unregister(char *);

extern int nvm_submit_io(struct nvm_dev *, struct nvm_rq *);
extern int nvm_erase_blk(struct nvm_dev *, struct nvm_block *);

static inline unsigned long nvm_get_rq_flags(struct request *rq)
{
	return (unsigned long)rq->cmd;
}

#else /* CONFIG_NVM */

struct nvm_dev_ops;

static inline int nvm_register(struct request_queue *q, char *disk_name,
							struct nvm_dev_ops *ops)
{
	return -EINVAL;
}
static inline void nvm_unregister(char *disk_name) {}

#endif /* CONFIG_NVM */
#endif /* LIGHTNVM.H */
