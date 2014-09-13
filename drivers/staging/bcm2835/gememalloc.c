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

#include <linux/broadcom/bcm_gememalloc_ioctl.h>

#include <linux/android_pmem.h>
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

#include "vc_util.h"

#if 0
# undef pr_debug
# define pr_debug pr_info
#endif

#define pgprot_cached(_prot)						\
	__pgprot((pgprot_val(_prot) & ~L_PTE_MT_MASK) | L_PTE_MT_WRITEBACK)


/*---------------------------------------------------------------------------*/

/*
 *
 */
struct alloc {
	vcmem_handle_t memh;
	dma_addr_t addr;
	size_t nr_bytes;
	struct list_head link;
};

/*
 *
 */
struct file_private_data {
	int id;
	/*
	 *
	 */
	struct mutex lock;
	struct alloc* pmem_region;
	struct list_head allocs;
};

static atomic_t file_cntr;
static dev_t dev;
static struct cdev cdev;
static struct class *device_class;

/*
 *
 */
static int create_alloc(size_t nr_bytes, struct alloc **allocp)
{
	struct alloc *alloc = *allocp = NULL;
	int result;
	vcmem_handle_t memh = VCMEM_HANDLE_INVALID;
	dma_addr_t addr;

	result = vcmem_alloc(nr_bytes, PAGE_SHIFT,
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
		result = -ENOMEM;
		goto err;
	}
	alloc->memh = memh;
	alloc->addr = addr;
	alloc->nr_bytes = nr_bytes;
	*allocp = alloc;
	return 0;

err:
	vcmem_unlock(memh);
	vcmem_release(&memh);
	kfree(alloc);
	return result;
}

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
	if (alloc == priv->pmem_region) {
		pr_debug("  destroying pmem-compat buffer\n");
		priv->pmem_region = NULL;
	}

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

static int ensure_pmem_buffer_locked(struct file_private_data *priv,
				     struct vm_area_struct *vma)
{
	size_t nr_bytes = vma->vm_end - vma->vm_start;
	int result;

	BUG_ON(!mutex_is_locked(&priv->lock));

	if (priv->pmem_region) {
		/*
		 * TODO: we really shouldn't let users mmap an
		 * existing pmem region for larger than its allocated
		 * size ... right?  But, the bmem_wrapper driver let
		 * that happen, so ...
		 */
		return 0;
	}

	pr_debug("  allocating 'special' pmem-compat buffer ...\n");

	result = create_alloc(nr_bytes, &priv->pmem_region);
	if (result) {
		return result;
	}
	list_add(&priv->pmem_region->link, &priv->allocs);
	return 0;
}

/*
 *
 */
static int acquire_buffer(struct file* file,
			  GEMemallocwrapParams *params)
{
	struct file_private_data *priv = file->private_data;
	int result;
	struct alloc *alloc;

	pr_debug("acquiring buffer of size %u from file %d ...\n",
		 params->size, priv->id);

	/* bmem_wrapper page-aligned allocation sizes, so we do here
	 * too. */
	params->size = ALIGN(params->size, PAGE_SIZE);
	params->busAddress = 0;

	result = create_alloc(params->size, &alloc);
	if (result) {
		return result;
	}

	mutex_lock(&priv->lock); {
		list_add(&alloc->link, &priv->allocs);
	} mutex_unlock(&priv->lock);

	params->busAddress = alloc->addr;
	return 0;
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
	priv->pmem_region = NULL;
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
			pr_err("Invalid arg pointer %p\n", uaddr);
			return -EFAULT;
		}
		return release_buffer_at(file, addr);
	}
	case PMEM_GET_PHYS: {
		struct pmem_region __user *uregion = (void*)arg;
		struct pmem_region region;

		mutex_lock(&priv->lock); {
			if (priv->pmem_region) {
				region.offset = priv->pmem_region->addr;
				region.len = priv->pmem_region->nr_bytes;
			} else {
				region.offset = 0;
				region.len = 0;
			}
		} mutex_unlock(&priv->lock);

		pr_debug("  pmem region at %#lx, size %lu\n",
			 region.offset, region.len);

		if (copy_to_user(uregion, &region, sizeof(*uregion))) {
			pr_err("Failed to copy outparams to %p\n", uregion);
			return -EFAULT;
		}
		return 0;
	}
	default:
		pr_err("Unknown ioctl %#x\n", cmd);
		BUG_ON("(unknown ioctl)");
		return -EINVAL;
	}
}

static int device_mmap_locked(struct file *file, struct vm_area_struct *vma)
{
	struct file_private_data *priv = file->private_data;
	int flags = 0;
	int result;
	struct alloc *alloc;

	if (!vma->vm_pgoff) {
		/*
		 *
		 */
		result = ensure_pmem_buffer_locked(priv, vma);
		if (result) {
			return result;
		}
		vma->vm_pgoff = priv->pmem_region->addr >> PAGE_SHIFT;
		flags = file->f_flags;
	}

	alloc = find_alloc_by_addr_locked(priv, vma->vm_pgoff << PAGE_SHIFT);
	if (!alloc) {
		pr_err("No allocation for file %d at offset %#lx\n",
		       priv->id, vma->vm_pgoff);
		return -EINVAL;
	}

	vma->vm_page_prot = (O_SYNC & flags) ?
			    pgprot_noncached(vma->vm_page_prot) :
			    pgprot_cached(vma->vm_page_prot);
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

	mutex_lock(&priv->lock); {
		result = device_mmap_locked(file, vma);
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
