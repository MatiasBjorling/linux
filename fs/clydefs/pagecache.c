#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include "clydefs.h"
#include "inode.h"
#include "pagecache.h"
#include "io.h"
/* FIXME :: inode's must point to these page cache functions */

#if 0
struct page_req
{

    struct inode *inode;
    unsigned expected_pages;

};

static void __page_req_init(struct page_req *r, unsigned expected_pages, struct inode *i)
{
    r->inode = i;
    r->expected_pages = expected_pages;
}

static int readpage_strip(void *data, struct page *p)
{
    /*struct page_collect *pcol = data;*/
    struct page_req *r = data;
    struct inode *i = r->inode;
    loff_t i_size = i_size_read(i);
    struct cfs_inode *ci = CFS_INODE(i);
    /*last page that could be mapped to this file*/
    pgoff_t end_ndx = i_size >> PAGE_CACHE_SHIFT;
    size_t len;
    int retval;

    /*require page to be locked and containing stale data*/
    BUG_ON(!PageLocked(p));
    if (PageUptodate(p)){
        CLYDE_ERR("PageUptodate true for (ino: 0x%lx, p->index: 0x%lx)\n", r->inode->i_ino, p->index);
        BUG();
    }
    if (p->index < end_ndx) {
        /*not last page, read it all*/
        len = PAGE_CACHE_SIZE;
    } else if (p->index == end_ndx) {
        /*last page, figure out how many remaining 
          bytes there is to read*/
        len = i_size & ~PAGE_CACHE_MASK;
    } else {
        /*out of bounds*/
        len = 0;
    }

    if (!len) {
        /*out-of bounds*/
        clear_highpage(p);
        SetPageUptodate(p);
        if (PageError(p)) {
            ClearPageError(p);
        }
    }
}


static int cfs_readpages(struct file *f, struct address_space *mapping, 
                         struct list_head *pages, unsigned nr_pages)
{
    return -1;
}
#endif

/** 
 * Calculates number of bytes to read/write based on the 
 * requested page in relation to the possible number of pages 
 * for the associated inode. 
 * @param p the requested page 
 * @return number of bytes to read, if not reading the last 
 *         page, a full page is to be read, otherwise reading as
 *         much of the last page as possible or nothing if the
 *         request is outside the inode's page range
 */
static __always_inline u64 page_ndx_to_bytes(struct page const * const p)
{
    u64 i_size = i_size_read(p->mapping->host);
    u64 end_ndx = i_size >> PAGE_CACHE_SHIFT;
    if (p->index < end_ndx) {
        /*not last page, read it all*/
        return PAGE_CACHE_SIZE;
    } else if (p->index == end_ndx) {
        /*last page, figure out how many remaining 
          bytes there is to read*/
        return (i_size & ~PAGE_CACHE_MASK);
    } else {
        /*out of bounds*/
        return 0;
    }
}

/** 
 * @pre i->i_mutex held 
 */ 
static __always_inline void __write_failed(struct inode *i, loff_t off)
{
    if (off > i->i_size) {
        /*were writing past end, truncate page to reflect current inode size*/
        truncate_pagecache(i, off, i->i_size);
    }
}

static __always_inline void __dbg_page_status(struct page *p)
{
    CFS_DBG(" PAGE [UptoDate:%s] [Dirty:%s] [Writeback:%s] [Locked:%s]\n",
            PageUptodate(p) ? "Y" : "N",
            PageDirty(p) ? "Y" : "N",
            PageWriteback(p) ? "Y" : "N",
            PageLocked(p) ? "Y" : "N");
}

/** 
 *  Read (at most) a page's worth of data into the supplied page
 *  as specified by the p->index offset.
 *  @param p page to read data into
 *  @param rwu true if this read is part of a read-write-update
 *             operation (i.e. called in preparation of a write
 *             smaller than a full page on an otherwise not
 *             updated page) -- if so, page will not be unlocked
 *             afterwards
 *  @pre PageLocked(p) => true
 *  @post if not rwu; page is unlocked and marked 'uptodate'
 */ 
static int cfsp_readpage(struct page *p, int rwu)
{
    /* 
        REQUIRED TO:
        - unlock and mark page uptodate after read completes
            [DONE]
        - see file "Locking" for more details!?
    */ 
    void *p_addr = NULL;
    struct inode *i = NULL;
    struct cfs_inode *ci = NULL;
    struct block_device *bd = NULL;
    u64 len;
    u64 off;
    int retval = 0;

    CFS_DBG("called\n");
    CLYDE_ASSERT(p != NULL);

    i = p->mapping->host;
    ci = CFS_INODE(i);
    bd = i->i_sb->s_bdev;

    /*get offset of request in bytes*/
    off = p->index >> PAGE_CACHE_SHIFT;
    
    __dbg_page_status(p);

    /*require page to be locked and containing stale data*/
    BUG_ON(!PageLocked(p));
    if (PageUptodate(p)){
        CLYDE_ERR("PageUptodate true for (ino: 0x%lx, p->index: 0x%lx)\n", i->i_ino, p->index);
        BUG();
    }
    len = page_ndx_to_bytes(p);

    if (!len) {
        /*out-of bounds*/
        CFS_WARN("attempted to read an out-of-bounds page\n");
        clear_highpage(p);
        SetPageUptodate(p);
        if (PageError(p)) {
            ClearPageError(p);
        }
    }
    
    p_addr = kmap(p);
    if (p_addr && len != 0) {
        retval = cfsio_read_node_sync(bd, NULL, NULL, ci->data.tid, ci->data.nid, off, len, p_addr);
        if (retval) {
            /*FIXME -- assume returning non-zero indicates an error and assume 
              not setting SetPageUptodate motivates whoever made the read
              request to try again*/
            CFS_WARN("failed to read a page in from node\n");
            retval = -1;
            goto out;
        }
        SetPageUptodate(p);

        if (!rwu) {
            /*just a regulard read which expects the page to be unlocked once done*/
            unlock_page(p);
        }
    } else {
        CFS_WARN("failed to translate supplied page into an actual address (using kmap(p) )\n");
    }
out:
    /*FIXME - when should I unmap a page ?*/
    kunmap(p);
    return retval;
}

/**
 *  @pre PageLocked(p) => true
 *  @post page is unlocked and marked 'uptodate'
 */ 
static int cfsp_aopi_readpage(struct file *f, struct page *p)
{
    /*isolated read page request, unlock page afterwards*/
    return cfsp_readpage(p, 0);
}

static int cfsp_write_begin(struct file *f, struct address_space *mapping, loff_t off, unsigned len, unsigned flags, struct page **pagep, void **fsdata)
{
    /* 
        REQUIRED TO:
        - check that the write can complete
            [DONE] (can't check)
        - allocate space if necessary
            [DONE] (not our problem)
        - [write updates parts of basic blocks]
            read in these blocks to writeouts work as intended
        - return the locked page for the specified offset, in pagep
            [DONE] - relying on simple_write_begin
        - must be able to cope with short-writes
            (short-write:: len passed to write begin exceeds number of bytes copied into the page)
        - return 0 on success, < 0 on failure, which ensures write_end isn't called
     
     
        - may return a void* in 'fsdata', gets passed to write_end
        - flags is a field for AOP_FLAG_XXX values, described in include/linux/fs.h
    */

    struct page *p = NULL;
    int retval;
    
    CFS_DBG("called\n");

    p = *pagep;
    if (p == NULL) {
        retval = simple_write_begin(f,mapping,off,len,flags,pagep,fsdata);
        if (retval) {
            CFS_DBG("simple_write_begin call returned with an error\n");
            goto out;
        }
    }

    if (!PageUptodate(p) && (len != PAGE_CACHE_SIZE)) {
        /*
            page is not up to date or we're writing less
            than the base unit of transfer which corresponds to
            a page - 
        */
        u64 read_bytes = page_ndx_to_bytes(p);

        if (!read_bytes) {
            /*out of range*/
            clear_highpage(p);
            SetPageUptodate(p);
            goto out;
        }
        
        /*read data in as part of an rwu operation*/
        retval = cfsp_readpage(p,1);
        if (retval) {
            unlock_page(p);
            CFS_DBG("failed to read page");
        }
    }
out:
    if (unlikely(retval)) {
        __write_failed(mapping->host, off+len);
    }
    return retval;
}

static int cfsp_aopi_write_begin(struct file *f, struct address_space *mapping, loff_t off, unsigned len, unsigned flags, struct page **pagep, void **fsdata)
{
    CFS_DBG("called\n");
    *pagep = NULL;
    return cfsp_write_begin(f,mapping,off,len,flags,pagep,fsdata);
}


/** 
 * @pre PG_Dirty has been cleared, PageLocked(p) => true 
 */ 
static int cfsp_aopi_writepage(struct page *p, struct writeback_control *wbc)
{
    /* 
        Required to:
        - set PG_writeback (enum pageflags, page_flags)
            [DONE]
        - unlock page, either synchronously or asynchronously when the operation completes
            [DONE]
        - [wbc->sync_mode == WB_SYNC_NONE -- ok to err out in case of errors]
            if aborting the writeout, return AOP_WRITEPAGE_ACTIVATE
        - see "Locking" file for more details !?
    */ 
    struct inode *i = NULL;
    struct cfs_inode *ci = NULL;
    struct block_device *bd = NULL;
    void *p_addr = NULL;
    u64 len;
    u64 off;
    int retval = 0;

    CFS_DBG("called\n");
    CLYDE_ASSERT(p != NULL);
    CLYDE_ASSERT(wbc != NULL);
    __dbg_page_status(p);
    i = p->mapping->host;
    ci = CFS_INODE(i);
    bd = i->i_sb->s_bdev;

    /*get offset of request in bytes*/
    off = p->index >> PAGE_CACHE_SHIFT;

    BUG_ON(!PageLocked(p));
    if (PageUptodate(p)){
        CLYDE_ERR("PageUptodate true for (ino: 0x%lx, p->index: 0x%lx)\n", i->i_ino, p->index);
        BUG();
    }
    len = page_ndx_to_bytes(p);

    p_addr = kmap(p);
    if (p_addr && len != 0) {
        set_page_writeback(p);
        retval = cfsio_update_node_sync(bd, NULL, NULL, ci->data.tid, ci->data.nid, off, len, p_addr);
        if (retval) {
            /*FIXME -- assume returning non-zero indicates an error and assume 
              not setting SetPageUptodate motivates whoever made the read
              request to try again*/
            CFS_WARN("failed to write page to node\n");
            retval = -1;
            goto out;
        }
        SetPageUptodate(p);
        end_page_writeback(p); /*why? logfs/file.c, clear_radix_tree_dirty -*/

        if (PageLocked(p)) {
            unlock_page(p); /*FIXME is this always a good idea ?*/
        }
    } else {
        CFS_WARN("failed to translate supplied page into an actual address (using kmap(p) )\n");
    }
out:
    kunmap(p);
    return retval;
}

static int cfsp_aopi_write_end(struct file *f, struct address_space *mapping, 
                         loff_t off, unsigned len, unsigned copied, 
                         struct page *p, void *fsdata)
{
    /*
        REQUIRED TO
        - unlock the page, release its refcount
        - update i_size
        - return < 0 on failure, otherwise no of bytes (<= 'copied')
            that were able to be copied into pagecache
     
        - 'len' is the original 'len' passed to write_begin
        - 'copied' => amount that was able to be copied
        - ONLY called after a SUCCESSFUL write_begin
    */
    struct inode *i = mapping->host;
    loff_t i_size = i->i_size; /*we hold i_mutex, so reading directly is ok*/
    int retval;

    CFS_DBG("called\n");

    /*will unlock & release the page (release=>refcount put operation), & update i_size*/
    retval = simple_write_end(f,mapping,off,len,copied,p,fsdata);
    if (unlikely(retval)) {
        __write_failed(i, off+len);
    }

    if (i_size != i->i_size) {
        /*size changed as a result of the write*/
        mark_inode_dirty(i);
    }

    return retval;
}

static int cfsp_releasepage(struct page *p, gfp_t gfp)
{ /*don't implement*/
    CFS_DBG("called\n");
    CFS_WARN("page 0x%lx released, STUB!\n", p->index);
    return 0;
}

static void cfsp_invalidatepage(struct page *p, unsigned long off)
{ /*don't implement*/
    CFS_DBG("called\n");
    CFS_WARN("page 0x%lx offset 0x%lx invalidated, STUB!\n", p->index, off);
    WARN_ON(1);
}

int cfsp_set_page_dirty(struct page *page)
{
    CFS_DBG("called\n");
    return __set_page_dirty_nobuffers(page);
}

const struct address_space_operations cfs_aops = {
    .readpage = cfsp_aopi_readpage,
    
    /*buffered writes*/
    .write_begin = cfsp_aopi_write_begin,
    .write_end = cfsp_aopi_write_end,

    /*mostly of interest to mmap'ed calls*/
    .writepage = cfsp_aopi_writepage,
    .writepages = generic_writepages, /*relies on .writepage*/

    .releasepage = cfsp_releasepage,
    .set_page_dirty = cfsp_set_page_dirty,
    .invalidatepage = cfsp_invalidatepage,
    .bmap = NULL,
    .direct_IO = NULL,
    .get_xip_mem = NULL,
    .migratepage = NULL,
    .launder_page = NULL,
    .is_partially_uptodate = NULL,
    .error_remove_page = NULL,
};
