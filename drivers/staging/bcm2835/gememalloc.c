/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */
/*******************************************************************************
Copyright 2010 Broadcom Corporation.  All rights reserved.

Unless you and Broadcom execute a separate written software license agreement
governing use of this software, this software is licensed to you under the
terms of the GNU General Public License version 2, available at
http://www.gnu.org/copyleft/gpl.html (the "GPL").

Notwithstanding the above, under no circumstances may you combine this software
in any way with any other Broadcom software provided under a license other than
the GPL, without Broadcom's express prior written consent.
*******************************************************************************/

#define DEV_NAME "gememalloc"

#define pr_fmt(fmt) DEV_NAME ":%s():%d: " fmt, __func__, __LINE__

#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/broadcom/bcm_gememalloc_ioctl.h>

#include <mach/vcio.h>

#undef pr_debug
#define pr_debug pr_info

#define pgprot_cached(_prot)						\
	__pgprot((pgprot_val(_prot) & ~L_PTE_MT_MASK) | L_PTE_MT_WRITEBACK)


/*-----------------------------------------------------------------------------
 * vcio.h ?
 */

#define max_sizeof(_a, _b)					\
	(sizeof(_a) > sizeof(_b) ? sizeof(_a) : sizeof(_b))

enum {
	VCMSG_OUTPARAMS_SIZE_MASK 	= ~VCMSG_REQUEST_SUCCESSFUL,
};

enum {
	VCMSG_MEM_ALLOC			= 0x0003000c,
	VCMSG_MEM_RELEASE		= 0x0003000f,
	VCMSG_MEM_LOCK			= 0x0003000d,
	VCMSG_MEM_UNLOCK		= 0x0003000e,
};

struct vcmsg_header {
	u32 msg_nr_bytes;
	u32 response;
	u32 tag;
	u32 buf_nr_bytes;
	union {
		u32 in_nr_bytes;
		u32 out_nr_bytes;
	};
};

struct vcmsg_footer {
	u32 end_tag;
};

#define VCMSG_TYPENAME(_tag)			\
	struct VCMSG_ ## _tag ## _struct

#define VCMSG_DEFINE(_tag, _inparams, _outparams)	\
	VCMSG_TYPENAME(_tag) {				\
		struct vcmsg_header hdr;		\
		union {					\
			struct {			\
				_inparams;		\
			} in;				\
			struct {			\
				_outparams;		\
			} out;				\
		};					\
		struct vcmsg_footer ftr;		\
	}

#define VCMSG_DECL(_tag, _var)			\
	VCMSG_TYPENAME(_tag) _var

#define VCMSG_SIZEOF_BUF(_m)				\
	(max_sizeof((_m).in, (_m).out))

#define VCMSG_DECL_INIT(_tag, _var, ...)				\
	VCMSG_DECL(_tag, _var) = {					\
		.hdr = {						\
			.msg_nr_bytes = sizeof(VCMSG_TYPENAME(_tag)),	\
			.response = 0,					\
			.tag = VCMSG_ ## _tag,				\
			.buf_nr_bytes = VCMSG_SIZEOF_BUF(_var),		\
			.in_nr_bytes = sizeof(_var.in),			\
		},							\
		.in = { __VA_ARGS__ },					\
		.ftr = { VCMSG_PROPERTY_END }				\
	}

#define is_vcmsg_success(_m)					\
	(VCMSG_REQUEST_SUCCESSFUL == (_m).hdr.response)

#define vcmsg_out_nr_bytes(_m)				\
	(VCMSG_OUTPARAMS_SIZE_MASK & (_m).hdr.out_nr_bytes)


VCMSG_DEFINE(MEM_ALLOC,
	     struct {
		     u32 size_bytes;
		     u32 align;
		     u32 flags;
	     },
	     u32 handle);

VCMSG_DEFINE(MEM_RELEASE,
	     u32 handle,
	     u32 error);

VCMSG_DEFINE(MEM_LOCK,
	     u32 handle,
	     u32 bus_addr);

VCMSG_DEFINE(MEM_UNLOCK,
	     u32 handle,
	     u32 error);

/*-----------------------------------------------------------------------------
 * vc_mem.h ?
 */
enum {
	VCMEM_FLAG_NONE			= 0,

	/*
	 * If a MEM_HANDLE_T is discardable, the memory manager may
	 * resize it to size 0 at any time when it is not locked or
	 * retained.
	 */
	VCMEM_FLAG_DISCARDABLE		= 1 << 0,
	/*
	 * If a MEM_HANDLE_T is allocating (or normal), its block of
	 * memory will be accessed in an allocating fashion through
	 * the cache.
	 */
	VCMEM_FLAG_NORMAL		= 0 << 2,
	VCMEM_FLAG_ALLOCATING		= VCMEM_FLAG_NORMAL,
	/*
	 * If a MEM_HANDLE_T is direct, its block of memory will be
	 * accessed directly, bypassing the cache.
	 */
	VCMEM_FLAG_DIRECT		= 1 << 2,
	/*
	 * If a MEM_HANDLE_T is coherent, its block of memory will be
	 * accessed in a non-allocating fashion through the cache.
	 */
	VCMEM_FLAG_COHERENT		= 2 << 2,
	/*
	 * If a MEM_HANDLE_T is L1-nonallocating, its block of memory
	 * will be accessed by the VPU in a fashion which is
	 * allocating in L2, but only coherent in L1.
	 */
	VCMEM_FLAG_L1_NONALLOCATING	= (VCMEM_FLAG_DIRECT |
					   VCMEM_FLAG_COHERENT),

	/*
	 * If a MEM_HANDLE_T is zero'd, its contents are set to 0
	 * rather than MEM_HANDLE_INVALID on allocation and resize up.
	 */
	VCMEM_FLAG_ZERO			= 1 << 4,
	/*
	 * If a MEM_HANDLE_T is uninitialised, it will not be reset to
	 * a defined value (either zero, or all 1's) on allocation.
	*/
	VCMEM_FLAG_NO_INIT		= 1 << 5,
	VCMEM_FLAG_INIT			= 0 << 5,

	/*
	 * Likely to be locked for long periods of time.
	 */
	VCMEM_FLAG_HINT_PERMALOCK	= 1 << 6,
	/*
	 * Likely to grow in size over time. If this flag is
	 * specified, MEM_FLAG_RESIZEABLE must also be.
	 */
	VCMEM_FLAG_HINT_GROW		= 1 << 7,

	/*
	 * If a MEM_HANDLE_T is to be resized with mem_resize, this
	 * flag must be present. This flag prevents things from being
	 * allocated out of the small allocation pool.
	 */
	VCMEM_FLAG_RESIZEABLE		= 1 << 8,
};
enum {
	VCMEM_HANDLE_INVALID	 	= 0x00000000ul,
	VCMEM_HANDLE_ZERO_SIZE_HANDLE	= 0x80000000ul,
	VCMEM_HANDLE_EMPTY_STRING_HANDLE= 0x80000001ul,
	VCMEM_HANDLE_FORCE_32_BIT 	= 0x80000000ul,
};

typedef u32 vcmem_handle_t;

static int vcmem_alloc(size_t nr_bytes, size_t align_lg2, int flags,
		       vcmem_handle_t* memh)
{
	VCMSG_DECL_INIT(MEM_ALLOC, msg,	{ nr_bytes, 1 << align_lg2, flags });
	int result = bcm_mailbox_property(&msg, sizeof(msg));
	if (result) {
		pr_err("Mailbox-send failed: %d\n", result);
		return result;
	}
	if (!is_vcmsg_success(msg)) {
		pr_err("VC request failed: %#x\n", msg.hdr.response);
		return -EIO;
	}
	BUG_ON(vcmsg_out_nr_bytes(msg) != sizeof(msg.out));
	*memh = msg.out.handle;
	return 0;
}

static int vcmem_release(vcmem_handle_t *memh)
{
	VCMSG_DECL_INIT(MEM_RELEASE, msg, *memh);
	int result = bcm_mailbox_property(&msg, sizeof(msg));
	if (result) {
		pr_err("Mailbox-send failed: %d\n", result);
		return result;
	}
	if (!is_vcmsg_success(msg)) {
		pr_err("VC request failed: %#x\n", msg.hdr.response);
		return -EIO;
	}
	BUG_ON(vcmsg_out_nr_bytes(msg) != sizeof(msg.out));
	if (0 != msg.out.error) {
		pr_err("MEM_RELEASE failed with error: %u\n", msg.out.error);
		return -ENXIO;
	}
	*memh = VCMEM_HANDLE_INVALID;
	return 0;
}

static int vcmem_lock(vcmem_handle_t memh, dma_addr_t* addr)
{
	VCMSG_DECL_INIT(MEM_LOCK, msg, memh);
	int result = bcm_mailbox_property(&msg, sizeof(msg));
	if (result) {
		pr_err("Mailbox-send failed: %d\n", result);
		return result;
	}
	if (!is_vcmsg_success(msg)) {
		pr_err("VC request failed: %#x\n", msg.hdr.response);
		return -EIO;
	}
	BUG_ON(vcmsg_out_nr_bytes(msg) != sizeof(msg.out));
	*addr = msg.out.bus_addr;
	return 0;
}

static int vcmem_unlock(vcmem_handle_t memh)
{
	VCMSG_DECL_INIT(MEM_UNLOCK, msg, memh);
	int result = bcm_mailbox_property(&msg, sizeof(msg));
	if (result) {
		pr_err("Mailbox-send failed: %d\n", result);
		return result;
	}
	if (!is_vcmsg_success(msg)) {
		pr_err("VC request failed: %#x\n", msg.hdr.response);
		return -EIO;
	}
	BUG_ON(vcmsg_out_nr_bytes(msg) != sizeof(msg.out));
	if (0 != msg.out.error) {
		pr_err("MEM_UNLOCK failed with error: %u\n", msg.out.error);
		return -ENXIO;
	}
	return 0;
}

/*---------------------------------------------------------------------------*/

/*
 *
 */
struct alloc {
	vcmem_handle_t memh;
	dma_addr_t addr;
	struct list_head link;
};

/*
 *
 */
struct file_private_data {
	int id;
	struct mutex lock;
	struct list_head allocs;
};

static atomic_t file_cntr;
static dev_t dev;
static struct cdev cdev;
static struct class *device_class;

static struct alloc *find_alloc_by_addr_locked(struct file_private_data* priv,
					       dma_addr_t addr)
{
	struct alloc *alloc;

	BUG_ON(!mutex_is_locked(&priv->lock));

	list_for_each_entry(alloc, &priv->allocs, link) {
		if (addr == alloc->addr) {
			return alloc;
		}
	}
	return NULL;
}

/*
 *
 */
static int destroy_alloc_locked(struct file_private_data* priv,
				struct alloc *alloc)
{
	int result = 0;

	BUG_ON(!mutex_is_locked(&priv->lock));

	list_del(&alloc->link);

	if (vcmem_unlock(alloc->memh)) {
		pr_err("Failed to unlock handle %#x, releasing anyway ...\n",
		       alloc->memh);
		result = -EINVAL;
		/* Continue on to attempt to release the handle. */
	}
	if (vcmem_release(&alloc->memh)) {
		pr_err("Failed to release handle %#x ... oh well\n",
		       alloc->memh);
		result = -ENXIO;
	}

	kfree(alloc);
	return result;
}

/*
 *
 */
static int acquire_buffer(struct file* file,
			  GEMemallocwrapParams *params)
{
	struct file_private_data *priv = file->private_data;
	int result;
	vcmem_handle_t memh = VCMEM_HANDLE_INVALID;
	dma_addr_t addr;
	struct alloc *alloc;

	pr_debug("acquiring buffer of size %u from file %d ...\n",
		 params->size, priv->id);

	/* bmem_wrapper page-aligned allocation sizes, so we do here
	 * too. */
	params->size = ALIGN(params->size, PAGE_SIZE);
	params->busAddress = 0;

	result = vcmem_alloc(params->size, PAGE_SHIFT,
			     (VCMEM_FLAG_ALLOCATING | VCMEM_FLAG_NO_INIT |
			      VCMEM_FLAG_HINT_PERMALOCK),
			     &memh);
	if (result) {
		goto err;
	}
	result = vcmem_lock(memh, &addr);
	if (result) {
		goto err;
	}

	pr_debug("  locked vcmem handle %#x to bus address %#x\n", memh, addr);

	alloc = kmalloc(sizeof(*alloc), GFP_KERNEL);
	if (!alloc) {
		pr_err("Failed to kmalloc allocation entry\n");
		goto err;
	}
	alloc->memh = memh;
	alloc->addr = addr;

	mutex_lock(&priv->lock); {
		list_add(&alloc->link, &priv->allocs);
	} mutex_unlock(&priv->lock);

	params->busAddress = addr;
	return 0;

err:
	vcmem_unlock(memh);
	vcmem_release(&memh);
	return result;
}

/*
 *
 */
static int release_buffer_at_locked(struct file_private_data *priv,
				    dma_addr_t addr)
{
	struct alloc *alloc;

	BUG_ON(!mutex_is_locked(&priv->lock));

	alloc = find_alloc_by_addr_locked(priv, addr);
	if (!alloc) {
		pr_err("Failed release of unknown or unowned buffer at %#x)\n",
		       addr);
		return -ENXIO;
	}
	return destroy_alloc_locked(priv, alloc);
}
static int release_buffer_at(struct file* file, dma_addr_t addr)
{
	struct file_private_data *priv = file->private_data;
	int result;

	pr_debug("releasing buffer at %#x from file %d\n", addr, priv->id);

	mutex_lock(&priv->lock); {
		result = release_buffer_at_locked(priv, addr);
	} mutex_unlock(&priv->lock);
	return result;
}

static int device_open(struct inode *inode, struct file *file)
{
	struct file_private_data *priv;

	pr_debug("opening new file ...\n");

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		pr_err("Failed to kmalloc private data\n");
		return -ENOMEM;
	}
	priv->id = atomic_inc_return(&file_cntr);
	mutex_init(&priv->lock);
	INIT_LIST_HEAD(&priv->allocs);

	pr_debug("  opened %d\n", priv->id);
	file->private_data = priv;
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	struct file_private_data *priv = file->private_data;
	struct alloc *alloc;
	struct alloc *tmp;

	pr_debug("releasing file %d\n", priv->id);

	/*
	 * No need to lock here because we have the last ref to the
	 * file and so must have exclusive access.  But lock anyway to
	 * make assertions happy, since it'll be uncontended.
	 */
	mutex_lock(&priv->lock); {
		list_for_each_entry_safe(alloc, tmp, &priv->allocs, link) {
			pr_debug("  (destroying still-alive alloc at %#x)\n",
				 alloc->addr);
			destroy_alloc_locked(priv, alloc);
		}
	} mutex_unlock(&priv->lock);
	kfree(priv);
	return 0;
}

static long device_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	struct file_private_data *priv = file->private_data;

	pr_debug("ioctl(%#x, arg=%#lx) on file %d\n", cmd, arg, priv->id);

	switch (cmd) {
	case GEMEMALLOC_WRAP_ACQUIRE_BUFFER: {
		GEMemallocwrapParams __user *uparams = (void*)arg;
		GEMemallocwrapParams params;
		int result;

		if (copy_from_user(&params, uparams, sizeof(params))) {
			pr_err("Invalid arg pointer %p\n", uparams);
			return -EFAULT;
		}
		result = acquire_buffer(file, &params);
		if (result) {
			return result;
		}
		if (copy_to_user(uparams, &params, sizeof(*uparams))) {
			pr_err("Failed to copy outparams to %p\n", uparams);
			return -EFAULT;
		}
		return 0;
	}
	case GEMEMALLOC_WRAP_RELEASE_BUFFER: {
		const dma_addr_t __user *uaddr = (void*)arg;
		dma_addr_t addr;

		if (copy_from_user(&addr, uaddr, sizeof(addr))) {
			return -EFAULT;
		}
		return release_buffer_at(file, addr);
	}
	default:
		pr_err("Unknown ioctl %#x\n", cmd);
		return -EINVAL;
	}
}

static int device_mmap_locked(struct file_private_data *priv,
			      struct vm_area_struct *vma)
{
	struct alloc *alloc =
		find_alloc_by_addr_locked(priv, vma->vm_pgoff << PAGE_SHIFT);

	if (!alloc) {
		pr_err("No allocation for file %d at offset %#lx\n",
		       priv->id, vma->vm_pgoff);
		return -EINVAL;
	}
	/* TODO: figure out caching semantics */
	vma->vm_page_prot = pgprot_cached(vma->vm_page_prot);
	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			    vma->vm_end - vma->vm_start,
			    vma->vm_page_prot)) {
		pr_err("Failed to mmap() region %#x in %d (addr=%#x)\n",
		       alloc->memh, priv->id, alloc->addr);
		/* bmem_wrapper returned this code in this case, so we
		 * do too. */
		return -EAGAIN;
	}
	pr_debug("  ok\n");
	return 0;
}
static int device_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file_private_data *priv = file->private_data;
	int result;

	pr_debug("mmap(file:%d off:%#lx) -> addr=%#lx ...\n",
		 priv->id, vma->vm_pgoff, vma->vm_start);

	if (!vma->vm_pgoff) {
		size_t nr_bytes = vma->vm_end - vma->vm_start;
		GEMemallocwrapParams params = { .size = nr_bytes };

		pr_debug("  doing 'special' pmem-compat acquire ...\n");

		result = acquire_buffer(file, &params);
		if (result) {
			return result;
		}
		vma->vm_pgoff = params.busAddress >> PAGE_SHIFT;
	}

	mutex_lock(&priv->lock); {
		result = device_mmap_locked(priv, vma);
	} mutex_unlock(&priv->lock);

	return result;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl,
	.mmap = device_mmap,
};

static void clean_up(void)
{
	device_destroy(device_class, dev);
	class_destroy(device_class);
	cdev_del(&cdev);
	unregister_chrdev_region(dev, 1);
}

static int __init gememalloc_init(void)
{
	int result;

	pr_info("Creating /dev/" DEV_NAME " ...\n");

	result = alloc_chrdev_region(&dev, 0, 1, DEV_NAME);
	if (0 > result) {
		pr_err("Failed to allocate dev\n");
		goto err;
	}

	cdev_init(&cdev, &fops);
	cdev.owner = THIS_MODULE;
	result = cdev_add(&cdev, dev, 1);
	if (0 > result) {
		pr_err("Failed to add cdev\n");
		goto err;
	}

	device_class = class_create(THIS_MODULE, DEV_NAME);
	if (IS_ERR(device_class)) {
		pr_err("Failed to create device class\n");
		result = PTR_ERR(device_class);
		goto err;
	}
	/* TODO: can this fail? */
	device_create(device_class, NULL, dev, NULL, DEV_NAME);

	pr_info("  success\n");
	return 0;
err:
	clean_up();
	return result;
}

static void __exit gememalloc_exit(void)
{
	pr_info("Goodbye\n");
	clean_up();
}

module_init(gememalloc_init);
module_exit(gememalloc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chris Jones");
MODULE_DESCRIPTION("Allocates direct-texturable and DMA-able 'video' memory");
