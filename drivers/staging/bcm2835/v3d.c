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

#define DEV_NAME "v3d"

#define pr_fmt(fmt) DEV_NAME ":%s():%d: " fmt, __func__, __LINE__

#include <linux/broadcom/v3d.h>

#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <mach/platform.h>

#include "v3d_regs.h"
#include "vc_util.h"

/*
 * Much of the information used to write this driver is taken from the
 * documentation of the VideoCore IV accelerated 3d graphics guide at
 *
 * http://www.broadcom.com/docs/support/videocore/VideoCoreIV-AG100-R.pdf
 */

/*
 * TODO: taken as-is from v3d_opt driver.  Tune this.  Can it really
 * be a constant or do we need to dynamically grow it?
 */
#define OOM_RESERVE_NR_BYTES (3 * (1 << 20))

/* v3d_opt used this timeout. */
#define ISR_TIMEOUT_MS 750

#if 0
#undef pr_debug
#define pr_debug pr_info
#endif

enum {
	V3D_RENDER_DONE = 1 << 0,
	V3D_BINNING_DONE = 1 << 1,
	V3D_THREAD_STATUS_MASK = (V3D_BINNING_DONE | V3D_RENDER_DONE),

	V3D_BINNING_OOM = 1 << 2,
};

enum {
	V3D_THREADCTL_ERROR = 1 << 3,
	V3D_THREADCTL_RUN = 1 << 5,
	V3D_THREADCTL_RESET = 1 << 15,
};

enum {
	V3D_L2_CACHE_ENABLED = 0,
	V3D_L2_CACHE_DISABLE = 1 << 1,
	V3D_L2_CACHE_CLEAR = 1 << 2,
};

enum {
	V3D_BIN_RENDER_COUNT_CLEAR = 0x1,
};

enum {
	V3D_SLICES_CACHECTL_CLEAR = 0x0f0f0f0f,
};

static void __iomem *v3d_iomem_base = (void*)IO_ADDRESS(V3D_BASE);

struct v3d_job {
	int dev_id;
	v3d_job_post_t spec;
	/* &c. */
};

struct oom_reserve {
	vcmem_handle_t memh;
	dma_addr_t addr;
	size_t nr_bytes;
};

struct file_private_data {
	int id;
	int finished_jobs;
};

static atomic_t file_cntr;
static dev_t dev;
static struct cdev cdev;
static struct class *device_class;
/* We use 2 OOM reserves because that's what the old v3d_opt driver did. */
static struct oom_reserve oom_reserves[2];
static int oom_reserve_idx;
static int status_flags;
static DECLARE_WAIT_QUEUE_HEAD(status_flags_changed);


static DEFINE_MUTEX(B3DL);


/*
 * TODO: make the reg param a strong type
 */
static void reg_write(u32 value, u32 reg)
{
	iowrite32(value, v3d_iomem_base + reg);
}

/*
 * TODO: make the reg param a strong type
 */
static u32 reg_read(u32 reg)
{
	return ioread32(v3d_iomem_base + reg);
}

static void qpu_reset(void)
{
	reg_write(V3D_THREADCTL_RESET, CT0CS);
	reg_write(V3D_THREADCTL_RESET, CT1CS);
}

static void regs_init(void)
{
	/* TODO v3d_opt driver did this, should we? */
	/*reg_write(V3D_L2_CACHE_DISABLE, L2CACTL);*/
	/* TODO dmaer driver did this */
	reg_write(V3D_L2_CACHE_CLEAR, L2CACTL);
	qpu_reset();
	reg_write(V3D_BIN_RENDER_COUNT_CLEAR, BFC);
	reg_write(V3D_BIN_RENDER_COUNT_CLEAR, RFC);
	reg_write(V3D_SLICES_CACHECTL_CLEAR, SLCACTL);
	reg_write(0, VPMBASE);
	reg_write(0, VPACNTL);
	reg_write(oom_reserves[0].addr, BPOA);
	reg_write(oom_reserves[0].nr_bytes, BPOS);
	reg_write(0xf, INTCTL);
	reg_write(0x7, INTENA);
}

static int alloc_oom_reserve(struct oom_reserve *reserve)
{
	int result;

	reserve->nr_bytes = OOM_RESERVE_NR_BYTES;
	/* TODO use dma_coherent for this? */
	result = vcmem_alloc(reserve->nr_bytes, PAGE_SHIFT,
			     /* TODO: cache coherency? */
			     VCMEM_FLAG_COHERENT | VCMEM_FLAG_HINT_PERMALOCK,
			     &reserve->memh);
	if (result) {
		pr_err("Failed to allocate OOM reserve\n");
		return result;
	}
	result = vcmem_lock(reserve->memh, &reserve->addr);
	if (result) {
		pr_err("Failed to lock OOM reserve into memory\n");
		return result;
	}

	pr_info("  oom reserve: %u bytes at %#x (handle %#x)\n",
		reserve->nr_bytes, reserve->addr, reserve->memh);
	return result;
}

static void free_oom_reserve(struct oom_reserve *reserve)
{
	vcmem_unlock(reserve->memh);
	vcmem_release(&reserve->memh);
}

static irqreturn_t handle_irq(int irq, void *unused)
{
	u32 flags, qpu_flags, tmp;
	irqreturn_t ret = IRQ_NONE;

	BUG_ON(IRQ_3D != irq);

	flags = reg_read(INTCTL);
	qpu_flags = reg_read(DBQITC);

	/* Clear interrupts we're going to handle. */
	tmp = flags & reg_read(INTENA);
	reg_write(tmp, INTCTL);
	if (qpu_flags) {
		reg_write(qpu_flags, DBQITC);
	}

	/* Save execution status for worker to read. */
	status_flags = (V3D_THREAD_STATUS_MASK & flags);

	if (V3D_BINNING_OOM & flags) {
		ret = IRQ_HANDLED;
		switch (oom_reserve_idx) {
		case 0:
		case 1:
			pr_debug("binning OOM: supplying reserve mem %d\n",
				 oom_reserve_idx);
			reg_write(oom_reserves[oom_reserve_idx].addr,
				  BPOA);
			reg_write(oom_reserves[oom_reserve_idx].nr_bytes,
				  BPOS);
			++oom_reserve_idx;
			break;
		default:
			pr_debug("binning OOM: exhausted reserves\n");
			/* Tell the worker this was an unrecoverable
			 * OOM. */
			status_flags |= V3D_BINNING_OOM;
			/* Disable OOM interrupt. */
			reg_write(V3D_BINNING_OOM, INTDIS);
			break;
		}
		/* (It's not known what this is for; seems redundant
		 * with above.) */
		reg_write(V3D_BINNING_OOM, INTCTL);
	}

	if (status_flags) {
		ret = IRQ_HANDLED;
		oom_reserve_idx = 0;
		wake_up_interruptible(&status_flags_changed);
	}
	return ret;
}

static int wait_for_status_flags_change(void)
{
	long timeout;
	do {
		timeout = wait_event_interruptible_timeout(status_flags_changed,
							   0 != status_flags,
							   msecs_to_jiffies(ISR_TIMEOUT_MS));
		
	} while (timeout < 0 && -ERESTARTSYS == timeout);
	return timeout > 0 ? 0 : (timeout < 0 ? timeout : -EBUSY);
}

static int run_render_job_direct(struct file_private_data *priv,
				 struct v3d_job *job)
{
	pr_debug("running render job ...\n");
	return -ENOSYS;

	/* reset 3d block */
	regs_init();
	/* check status */
	reg_write(job->spec.v3d_ct1ca, CT1CA);
	reg_write(job->spec.v3d_ct1ea, CT1EA);

	/* await ... ? */

	return 0;
}

static int run_bin_render_job_direct(struct file_private_data *priv,
				     struct v3d_job *job)
{
	int result;

	pr_debug("running binning+render job ...\n");

	/* TODO: reset 3d block? */
	regs_init();
	status_flags = 0;

	/* Binning. */
	reg_write(V3D_THREADCTL_RUN, CT0CS);
	reg_write(job->spec.v3d_ct0ca, CT0CA);
	reg_write(job->spec.v3d_ct0ea, CT0EA);

	result = wait_for_status_flags_change();
	if (result) {
		pr_err("Failed to wait for binning to complete: %d\n",
			result);
		goto err;
	}
	if (V3D_BINNING_OOM & status_flags) {
		pr_err("OOM during binning: aborting job\n");
		goto err;
	}
	BUG_ON(1 != reg_read(BFC) || !(V3D_BINNING_DONE & status_flags));
	status_flags = 0;

	/* Render. */
	reg_write(V3D_SLICES_CACHECTL_CLEAR, SLCACTL);
	reg_write(V3D_THREADCTL_RUN, CT1CS);
	reg_write(job->spec.v3d_ct1ca, CT1CA);
	reg_write(job->spec.v3d_ct1ea, CT1EA);

	result = wait_for_status_flags_change();
	if (result) {
		pr_err("Failed to wait for render to complete: %d\n",
			result);
		goto err;
	}
	BUG_ON(1 != reg_read(RFC) || !(V3D_RENDER_DONE & status_flags));

	pr_debug("  bin+render seems to have finished successfully\n");
	++priv->finished_jobs;
	goto out;
err:
	qpu_reset();
	reg_write(V3D_SLICES_CACHECTL_CLEAR, SLCACTL);
out:
	status_flags = 0;
	return result;
}

static int job_post(struct file_private_data *priv, const v3d_job_post_t *spec)
{
	struct v3d_job *job = NULL;
	int result;

	pr_debug("posting job to file %d\n", priv->id);


	mutex_lock(&B3DL);


	job = kmalloc(sizeof(*job), GFP_KERNEL);
	if (!job) {
		pr_err("Failed to kmalloc v3d job\n");
		result = -ENOMEM;
		goto err;
	}
	job->dev_id = priv->id;
	memcpy(&job->spec, spec, sizeof(job->spec));

	switch (job->spec.job_type) {
	case V3D_JOB_REND:
		result = run_render_job_direct(priv, job);
		goto out;
	case V3D_JOB_BIN_REND:
		result = run_bin_render_job_direct(priv, job);
		goto out;
	default:
		pr_err("Post of unsupported job type %d\n", spec->job_type);
		result = -EINVAL;
		goto err;
	}
err:
out:


	mutex_unlock(&B3DL);


	pr_debug("  finished job\n");

	kfree(job);
	return result;
}

static int job_wait(struct file_private_data *priv, v3d_job_status_t* status)
{
	pr_debug("waiting on job for file %d\n", priv->id);


	mutex_lock(&B3DL);


	/* TODO */
	if (priv->finished_jobs > 0) {
		status->job_status = V3D_JOB_STATUS_SUCCESS;
		--priv->finished_jobs;
		pr_debug("  succeeded %d jobs ago\n", priv->finished_jobs);
	} else {
		status->job_status = V3D_JOB_STATUS_NOT_FOUND;
		pr_debug("  no completed jobs\n");
	}


	mutex_unlock(&B3DL);


	return 0;
}

static int device_open(struct inode *inode, struct file *file)
{
	struct file_private_data *priv;

	pr_debug("opening new file ...\n");

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		pr_err("Failed to kmalloc private data");
		return -ENOMEM;
	}
	memset(priv, 0, sizeof(*priv));
	priv->id = atomic_inc_return(&file_cntr);
	priv->finished_jobs = 0;

	pr_debug("  opened %d\n", priv->id);
	file->private_data = priv;
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	struct file_private_data *priv = file->private_data;

	pr_debug("releasing file %d\n", priv->id);

	kfree(priv);
	return 0;
}

static long device_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	struct file_private_data *priv = file->private_data;

	pr_debug("ioctl(%#x, arg=%#lx) on file %d\n", cmd, arg, priv->id);

	switch (cmd) {
	case V3D_IOCTL_POST_JOB: {
		const v3d_job_post_t __user *uspec = (void*)arg;
		v3d_job_post_t spec;

		if (copy_from_user(&spec, uspec, sizeof(spec))) {
			pr_err("Invalid arg pointer %p\n", uspec);
			return -EFAULT;
		}
		return job_post(priv, &spec);
	}
	case V3D_IOCTL_WAIT_JOB: {
		v3d_job_status_t __user *ustatus = (void*)arg;
		v3d_job_status_t status;
		int result;

		if (copy_from_user(&status, ustatus, sizeof(status))) {
			pr_err("Invalid arg pointer %p\n", ustatus);
			return -EFAULT;
		}

		result = job_wait(priv, &status);

		if (copy_to_user(ustatus, &status, sizeof(*ustatus))) {
			pr_err("Failed to copy outparams to %p\n", ustatus);
			/*
			 * Prefer returning the error code from
			 * |job_wait()|, if there was one.
			 */
			result = result || -EFAULT;
		}
		return result;
	}
	default:
		pr_err("Unknown ioctl %#x\n", cmd);
		BUG_ON("(unknown ioctl)");
		return -EINVAL;
	}
}

static int device_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file_private_data *priv = file->private_data;

	pr_debug("mapping file %d\n", priv->id);

	return -ENODEV;
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
	free_irq(IRQ_3D, &dev);
	device_destroy(device_class, dev);
	class_destroy(device_class);
	cdev_del(&cdev);
	unregister_chrdev_region(dev, 1);
	free_oom_reserve(&oom_reserves[0]);
	free_oom_reserve(&oom_reserves[1]);
	vcqpu_set_state(VCQPU_DISABLED);
}

/* TODO: suspend/resume through platform_driver_register()? */

static int __init v3d_init(void)
{
	int result;
	union {
		u32 num;
		char str[4];
	} ident;

	pr_info("Initializing v3d (registers mapped at %p) ...\n",
		v3d_iomem_base);

	result = vcqpu_set_state(VCQPU_ENABLED);
	if (result) {
		pr_err("Failed to enable 3d block\n");
		goto err;
	}
	ident.num = reg_read(IDENT0);
	pr_info("  core identifies as '%c%c%c' version %d\n",
		ident.str[0], ident.str[1], ident.str[2], ident.str[3]);
	if (strncmp("V3D", ident.str, 3) || 2 != ident.str[3]) {
		pr_err("Unknown VideoCore 3d block identity or version\n");
		result = -ENODEV;
		goto err;
	}
	qpu_reset();

	result = alloc_oom_reserve(&oom_reserves[0]);
	if (result) {
		goto err;
	}
	result = alloc_oom_reserve(&oom_reserves[1]);
	if (result) {
		goto err;
	}

	pr_info("  creating /dev/" DEV_NAME " ...\n");
	result = alloc_chrdev_region(&dev, 0, 1, DEV_NAME);
	if (result) {
		pr_err("Failed to allocate dev\n");
		goto err;
	}
	cdev_init(&cdev, &fops);
	cdev.owner = THIS_MODULE;
	result = cdev_add(&cdev, dev, 1);
	if (result) {
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

	result = request_irq(IRQ_3D, handle_irq, IRQF_SHARED, DEV_NAME, &dev);
	if (result) {
		pr_err("Failed to install isr for v3d irq\n");
		goto err;
	}

	pr_info("  success\n");
	return 0;
err:
	clean_up();
	return result;
}

static void __exit v3d_exit(void)
{
	pr_info("Goodbye\n");
	clean_up();
}

module_init(v3d_init);
module_exit(v3d_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Broadcom Corporation");
MODULE_DESCRIPTION("V3D device driver");
