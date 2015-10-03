#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <linux/pagemap.h>

#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/bio.h>
#include <linux/fs.h>

#include "usio.h"

static long usio_submit(struct usio_io *io)
{
	struct inode *inode;
	struct block_device *bdev;
	struct file *filep;
	struct bio *bio;
	struct page **pages;
	int err = 0, npages, i;

	if ((io->io_buffer & PAGE_MASK) != io->io_buffer)
		return -EINVAL;

	if ((io->io_nbytes & PAGE_MASK) != io->io_nbytes)
		return -EINVAL;

	if (io->io_offset & ((1ul << 9) - 1))
		return -EINVAL;

	npages = io->io_nbytes >> PAGE_SHIFT;
	pages = kmalloc(npages * sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	err = get_user_pages_fast(io->io_buffer, npages, 0, pages);
	if (err < 0)
		goto free_pages;

	if (err != npages) {
		for (i = 0; i != err; ++i)
			page_cache_release(pages[i]);
		err = -ENOMEM;
		goto free_pages;
	}

	filep = fget(io->io_filed);
	if (!filep) {
		err = -EBADF;
		goto release_pages;
	}

	if (!filep->f_mapping) {
		err = -EINVAL;
		goto put_file;
	}

	inode = filep->f_mapping->host;
	if (!inode || !(inode->i_mode & S_IFBLK)) {
		err = -EINVAL;
		goto put_file;
	}

	bdev = I_BDEV(inode);
	pr_err("bdev pointer is %lx\n", (unsigned long)bdev);
	pr_err("bdev->bd_inode is %lx\n", (unsigned long)bdev->bd_inode);
	bio = bio_alloc(GFP_NOIO, BIO_MAX_PAGES);
	if (!bio) {
		err = -ENOMEM;
		goto put_file;
	}

	bio->bi_bdev = bdev;
	bio->bi_iter.bi_sector = io->io_offset >> 9;

	for (i = 0; i != npages; ++i) {
		if (bio_add_page(bio, pages[i], PAGE_SIZE, 0) != PAGE_SIZE) {
			err = -EIO;
			goto release_bio;
		}
	}

	bio_get(bio);
	submit_bio_wait(REQ_WRITE, bio);

release_bio:
	bio_put(bio);
put_file:
	fput(filep);
release_pages:
	for (i = 0; i != npages; ++i)
		page_cache_release(pages[i]);
free_pages:
	kfree(pages);
	return err;
}

static long usio_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct usio_io io;

	if (_IOC_TYPE(cmd) != USIO_IOC_MAGIC)
		return -ENOTTY;

	if (_IOC_NR(cmd) > USIO_IOC_MAXNR)
		return -ENOTTY;

	if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
		return -EFAULT;

	return usio_submit(&io);
}

static const struct file_operations usio_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = usio_ioctl,
};

static struct miscdevice usio_dev = {
	.name = "usio",
	.fops = &usio_fops,
	.minor = MISC_DYNAMIC_MINOR,
	.mode = S_IWUSR | S_IWGRP,
};

static int __init usio_init(void)
{
	const int rc = misc_register(&usio_dev);

	if (rc)
		pr_debug("misc_register failed\n");

	return 0;
}

static void __exit usio_exit(void)
{
	misc_deregister(&usio_dev);
}

module_init(usio_init);
module_exit(usio_exit);

MODULE_LICENSE("GPL");
