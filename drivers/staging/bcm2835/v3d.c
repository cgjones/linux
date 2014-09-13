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
 * TODO: taken as-is from v3d_opt driver.  Tune this.  Can it really
 * be a constant or do we need to dynamically grow it?
 */
#define OOM_RESERVE_NR_BYTES (3 * (1 << 20))

#undef pr_debug
#define pr_debug pr_info

static void __iomem *v3d_iomem_base = (void*)IO_ADDRESS(V3D_BASE);

struct v3d_job {
	int dev_id;
	v3d_job_post_t spec;
	/* &c. */
};

struct file_private_data {
	int id;
	int finished_jobs;
};

static atomic_t file_cntr;
static dev_t dev;
static struct cdev cdev;
static struct class *device_class;
static vcmem_handle_t oom_reserve_handle = VCMEM_HANDLE_INVALID;
static dma_addr_t oom_reserve;
/*static dma_addr_t oom_block2; ???*/


DEFINE_MUTEX(B3DL);



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

static void regs_reset(void)
{
	reg_write(2, L2CACTL);
	reg_write(0x8000, CT0CS);
	reg_write(0x8000, CT1CS);
	reg_write(1, RFC);
	reg_write(1, BFC);
	reg_write(0x0f0f0f0f, SLCACTL);
	reg_write(0, VPMBASE);
	reg_write(0, VPACNTL);
	reg_write(oom_reserve, BPOA);
	reg_write(OOM_RESERVE_NR_BYTES, BPOS);
	reg_write(0xf, INTCTL);
	reg_write(0x7, INTENA);
}

static void qpu_reset(void)
{
	reg_write(CT0CS, 1 << 15);
	reg_write(CT1CS, 1 << 15);
}

static int run_render_job_direct(struct file_private_data *priv,
				 struct v3d_job *job)
{
	pr_debug("running binning+render job ...\n");
	return -ENOSYS;

	/* reset 3d block */
	regs_reset();
	/* check status */
	reg_write(job->spec.v3d_ct1ca, CT1CA);
	reg_write(job->spec.v3d_ct1ea, CT1EA);

	/* await ... ? */

	return 0;
}

#define MAX_ATTEMPTS (1 << 20)

static int run_bin_render_job_direct(struct file_private_data *priv,
				     struct v3d_job *job)
{
	int result = 0;
	u32 initial_bfc, initial_rfc;
	int attempts;

	pr_debug("running binning+render job ...\n");

	/* reset 3d block */
	regs_reset();

	/*
	 * TODO: this is a hack to stand things up.  We want to be
	 * using interrupts for status updates.
	 */

	initial_bfc = reg_read(BFC) & 0xff;
	initial_rfc = reg_read(RFC) & 0xff;
	pr_debug("  initially BFC=%d, RFC=%d\n", initial_bfc, initial_rfc);

	/* Binning? */
	reg_write(job->spec.v3d_ct0ca, CT0CA);
	reg_write(job->spec.v3d_ct0ea, CT0EA);
	for (attempts = 0; attempts < MAX_ATTEMPTS; ++attempts) {
		u32 bfc;

		cpu_relax();

		bfc = reg_read(BFC) & 0xff;
		if (bfc == ((initial_bfc + 1) & 0xff)) {
			pr_debug("  binning completed! after %d checks\n",
				 attempts);
			break;
		}
	}
	if (MAX_ATTEMPTS == attempts) {
		pr_err("Binning didn't complete within %d checks\n",
		       attempts);
		result = -EBUSY;
		goto err;
	}

	/* Render? */
	reg_write(job->spec.v3d_ct1ca, CT1CA);
	reg_write(job->spec.v3d_ct1ea, CT1EA);
	for (attempts = 0; attempts < MAX_ATTEMPTS; ++attempts) {
		u32 rfc;

		schedule();

		rfc = reg_read(RFC) & 0xff;
		if (rfc == ((initial_rfc + 1) & 0xff)) {
			pr_debug("  render completed!(?) after %d checks\n",
				 attempts);
			break;
		}
	}
	if (MAX_ATTEMPTS == attempts) {
		pr_err("Render didn't complete(?) within %d checks\n",
		       attempts);
		result = -EBUSY;
		goto err;
	}

	for (attempts = 0; attempts < MAX_ATTEMPTS; ++attempts) {
		u32 pcs;

		schedule();

		pcs = reg_read(PCS);
		if (0 == pcs) {
			pr_debug("  pcs is 0. Yay?\n");
			break;
		}
	}
	if (MAX_ATTEMPTS == attempts) {
		pr_err("PCS reg didn't reach 0(?) within %d checks\n",
		       attempts);
		result = -EBUSY;
		goto err;
	}

	pr_debug("  bin+render seems to have finished successfully\n");
	++priv->finished_jobs;
	return 0;

err:
	qpu_reset();
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
	device_destroy(device_class, dev);
	class_destroy(device_class);
	cdev_del(&cdev);
	unregister_chrdev_region(dev, 1);
	vcmem_unlock(oom_reserve_handle);
	vcmem_release(&oom_reserve_handle);
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

	result = vcmem_alloc(OOM_RESERVE_NR_BYTES, PAGE_SHIFT,
			     /* TODO: cache coherency? */
			     VCMEM_FLAG_COHERENT | VCMEM_FLAG_HINT_PERMALOCK,
			     &oom_reserve_handle);
	if (result) {
		pr_err("Failed to allocate OOM reserve\n");
		goto err;
	}
	result = vcmem_lock(oom_reserve_handle, &oom_reserve);
	if (result) {
		pr_err("Failed to lock OOM reserve into memory\n");
		goto err;
	}
	pr_info("  oom reserve: %u bytes at %#x (handle %#x)\n",
		OOM_RESERVE_NR_BYTES, oom_reserve, oom_reserve_handle);

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
