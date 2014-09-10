/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#define DEV_NAME "gememalloc"

#define pr_fmt(fmt) DEV_NAME ":%s():%d: " fmt, __func__, __LINE__

#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/broadcom/bcm_gememalloc_ioctl.h>

#undef pr_debug
#define pr_debug pr_info

struct file_private_data {
	int id;
};

static atomic_t file_cntr;
static dev_t dev;
static struct cdev cdev;
static struct class *device_class;

/*
 *
 */
static int acquire_buffer(struct file* file,
			  const GEMemallocwrapParams *params)
{
	struct file_private_data* priv = file->private_data;

	pr_debug("acquiring buffer of size %u from file %d\n",
		 params->size, priv->id);

	return -ENOMEM;
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
	case GEMEMALLOC_WRAP_ACQUIRE_BUFFER: {
		const GEMemallocwrapParams __user *uparams = (void*)arg;
		GEMemallocwrapParams params;

		if (copy_from_user(&params, uparams, sizeof(params))) {
			pr_err("Invalid arg pointer %p\n", uparams);
			return -EINVAL;
		}
		return acquire_buffer(file, &params);
	}
	default:
		pr_err("Unknown ioctl %#x\n", cmd);
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
