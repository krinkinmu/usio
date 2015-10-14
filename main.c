#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <linux/pagemap.h>

#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/bio.h>
#include <linux/fs.h>

#include "usio.h"

struct usio_context {
	spinlock_t lock;
	struct list_head finished_list;
	size_t finished_list_size;
	struct list_head running_list;
	wait_queue_head_t finished_wq;
};

struct usio_io_handle {
	struct list_head link;
	struct bio *bio;
	struct usio_event event;
	struct usio_context *ctx;
	struct work_struct complete_work;
};

static struct kmem_cache *usio_io_handle_cachep;


static void usio_bio_release_pages(struct bio *bio)
{
	struct bio_vec *bvec;
	unsigned i;

	bio_for_each_segment_all(bvec, bio, i)
		page_cache_release(bvec->bv_page);
}

static void usio_end_io(struct bio *bio)
{
	struct usio_io_handle *handle = bio->bi_private;
	struct usio_context *ctx = handle->ctx;

	handle->event.res = bio->bi_error;
	usio_bio_release_pages(bio);
	bio_put(bio);

	spin_lock(&ctx->lock);
	++ctx->finished_list_size;
	list_move(&handle->link, &ctx->finished_list);
	spin_unlock(&ctx->lock);

	wake_up(&ctx->finished_wq);
}

static struct bio *usio_bio_create(struct usio_io *io,
			struct block_device *bdev)
{
	struct page **pages;
	struct bio *bio;
	__u64 last = io->data + io->bytes + PAGE_SIZE - 1;
	int npages;
	int offset, len;
	int rc, i;

	npages = (last >> PAGE_SHIFT) - (io->data >> PAGE_SHIFT);
	if (npages > BIO_MAX_PAGES)
		return ERR_PTR(-EINVAL);

	bio = bio_alloc(GFP_KERNEL, npages);
	bio->bi_bdev = bdev;
	bio->bi_iter.bi_sector = io->offset >> 9;
	bio->bi_end_io = usio_end_io;

	pages = kcalloc(npages, sizeof(*pages), GFP_KERNEL);
	if (!pages) {
		bio_put(bio);
		return ERR_PTR(-ENOMEM);
	}

	rc = get_user_pages_fast(io->data & PAGE_MASK, npages,
				(io->flags & REQ_WRITE) != REQ_WRITE, pages);
	if (rc < npages) {
		rc = -EFAULT;
		goto out;
	}

	rc = 0;
	offset = io->data & ~PAGE_MASK;
	len = io->bytes;
	for (i = 0; i != npages; ++i) {
		unsigned bytes = PAGE_SIZE - offset;

		if (bytes > len)
			bytes = len;

		if (bio_add_page(bio, pages[i], bytes, offset) != bytes) {
			rc = -EFAULT;
			goto out;
		}

		offset = 0;
		len -= bytes;
	}

out:
	if (rc) {
		bio_put(bio);
		for (i = 0; i != npages; ++i) {
			if (!pages[i])
				break;
			page_cache_release(pages[i]);
		}
	}

	kfree(pages);
	return rc ? ERR_PTR(rc) : bio;
}

static long usio_submit_one(struct usio_context *ctx,
			struct usio_io __user *uio, struct usio_io *io)
{
	struct file *filep = fget(io->fd);
	struct block_device *bdev;
	struct usio_io_handle *handle;
	struct inode *inode;
	struct bio *bio;
	unsigned blksize_mask;
	unsigned long flags;

	if (!filep || !filep->f_mapping)
		return -EBADF;

	inode = filep->f_mapping->host;
	if (!inode || !(inode->i_mode & S_IFBLK)) {
		fput(filep);
		return -EINVAL;
	}

	bdev = I_BDEV(inode);
	blksize_mask = (1 << blksize_bits(bdev_logical_block_size(bdev))) - 1;

	if (io->offset & blksize_mask) {
		fput(filep);
		return -EINVAL;
	}

	handle = kmem_cache_alloc(usio_io_handle_cachep, GFP_KERNEL);
	if (!handle) {
		fput(filep);
		return -ENOMEM;
	}

	bio = usio_bio_create(io, bdev);
	if (IS_ERR(bio)) {
		kmem_cache_free(usio_io_handle_cachep, handle);
		fput(filep);
		return PTR_ERR(bio);
	}

	bio->bi_private = handle;
	handle->ctx = ctx;
	handle->event.io = (__u64)uio;
	handle->event.res = 0;
	handle->bio = bio;

	spin_lock_irqsave(&ctx->lock, flags);
	list_add_tail(&handle->link, &ctx->running_list);
	spin_unlock_irqrestore(&ctx->lock, flags);

	submit_bio(io->flags, bio);
	fput(filep);

	return 0;
}

static long usio_submit_all(struct usio_context *ctx,
			struct usio_ios __user *ios)
{
	struct usio_ios copy;
	struct blk_plug plug;

	struct usio_io __user *__user *iopp;
	long count, i, rc;

	if (copy_from_user(&copy, ios, sizeof(copy)))
		return -EFAULT;

	iopp = copy.ios;
	count = copy.count;

	if (!access_ok(VERIFY_READ, iopp, count * sizeof(*iopp)))
		return -EFAULT;

	blk_start_plug(&plug);
	for (i = 0; i < count; ++i) {
		struct usio_io __user *io;
		struct usio_io tmp;

		if (__get_user(io, iopp + i)) {
			rc = -EFAULT;
			break;
		}

		if (copy_from_user(&tmp, io, sizeof(tmp))) {
			rc = -EFAULT;
			break;
		}

		rc = usio_submit_one(ctx, io, &tmp);
		if (rc)
			break;
	}
	blk_finish_plug(&plug);

	return i ? i : rc;
}

static size_t usio_ctx_finished(struct usio_context *ctx)
{
	unsigned long flags;
	size_t ret;

	spin_lock_irqsave(&ctx->lock, flags);
	ret = ctx->finished_list_size;
	spin_unlock_irqrestore(&ctx->lock, flags);

	return ret;
}

static long usio_reclaim(struct usio_context *ctx,
			struct usio_events __user *uevents)
{
	struct usio_events copy;
	struct usio_event __user *events;
	unsigned long flags;
	long finished;
	long min_count;
	long max_count;
	struct list_head splice;
	struct list_head *pos, *tmp;
	long rc = 0, i = 0;

	if (copy_from_user(&copy, uevents, sizeof(copy)))
		return -EFAULT;

	events = copy.events;
	min_count = copy.min_count;
	max_count = copy.max_count;

	if (!access_ok(VERIFY_WRITE, events, max_count * sizeof(*events)))
		return -EFAULT;

	wait_event_interruptible(ctx->finished_wq,
				usio_ctx_finished(ctx) < min_count);

	if (signal_pending(current))
		return -EINTR;

	INIT_LIST_HEAD(&splice);

	spin_lock_irqsave(&ctx->lock, flags);
	list_splice_init(&ctx->finished_list, &splice);
	finished = ctx->finished_list_size;
	ctx->finished_list_size = 0;
	spin_unlock_irqrestore(&ctx->lock, flags);

	list_for_each_safe(pos, tmp, &splice) {
		struct usio_io_handle *handle = list_entry(pos,
					struct usio_io_handle, link);
		struct usio_event *event = &handle->event;

		if (i == max_count)
			break;

		if (__copy_to_user(events + i, event, sizeof(*event))) {
			rc = -EFAULT;
			break;
		}

		list_del(pos);
		kmem_cache_free(usio_io_handle_cachep, handle);
		++i;
	}

	if (!list_empty(&splice)) {
		spin_lock_irqsave(&ctx->lock, flags);
		list_splice_tail(&splice, &ctx->finished_list);
		ctx->finished_list_size += finished - i;
		spin_unlock_irqrestore(&ctx->lock, flags);

		wake_up(&ctx->finished_wq);
	}

	return i ? i : rc;
}

static long usio_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct usio_context *ctx = filep->private_data;
	int rc = 0;

	if (_IOC_TYPE(cmd) != USIO_IOC_MAGIC)
		return -ENOTTY;

	if (_IOC_NR(cmd) > USIO_IOC_MAXNR)
		return -ENOTTY;

	switch (cmd) {
	case USIO_SUBMIT:
		rc = usio_submit_all(ctx, (struct usio_ios __user *)arg);
		break;
	case USIO_RECLAIM:
		pr_info("received USIO_RECLAIM request\n");
		rc = usio_reclaim(ctx, (struct usio_events __user *)arg);
		break;
	default:
		pr_info("received unknown request\n");
		return -ENOTTY;
	}

	pr_info("return %d\n", rc);
	return rc;
}

static int usio_open(struct inode *inode, struct file *file)
{
	struct usio_context *ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);

	if (!ctx) {
		pr_err("Cannot allocate usio_context\n");
		return -ENOMEM;
	}

	spin_lock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->finished_list);
	ctx->finished_list_size = 0;
	INIT_LIST_HEAD(&ctx->running_list);
	init_waitqueue_head(&ctx->finished_wq);
	file->private_data = ctx;

	return 0;
}

static int usio_release(struct inode *inode, struct file *file)
{
	struct usio_context *ctx = (struct usio_context *)file->private_data;
	struct list_head *pos, *tmp;

	wait_event(ctx->finished_wq, list_empty(&ctx->running_list));
	list_for_each_safe(pos, tmp, &ctx->finished_list) {
		struct usio_io_handle *handle = list_entry(pos,
					struct usio_io_handle, link);
		kmem_cache_free(usio_io_handle_cachep, handle);
	}
	kfree(ctx);

	return 0;
}

static const struct file_operations usio_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = usio_ioctl,
	.open = usio_open,
	.release = usio_release,
};

static struct miscdevice usio_dev = {
	.name = "usio",
	.fops = &usio_fops,
	.minor = MISC_DYNAMIC_MINOR,
	.mode = S_IWUSR | S_IWGRP,
};

static int __init usio_init(void)
{
	int rc;

	usio_io_handle_cachep = KMEM_CACHE(usio_io_handle, 0);
	if (!usio_io_handle_cachep) {
		pr_err("Cannot create usio_io_handle cache\n");
		return -ENOMEM;
	}

	if ((rc = misc_register(&usio_dev))) {
		kmem_cache_destroy(usio_io_handle_cachep);
		pr_err("Cannot register misc device\n");
		return rc;
	}

	return 0;
}

static void __exit usio_exit(void)
{
	misc_deregister(&usio_dev);
	kmem_cache_destroy(usio_io_handle_cachep);
}

module_init(usio_init);
module_exit(usio_exit);

MODULE_LICENSE("GPL");
