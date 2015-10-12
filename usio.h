#ifndef __USIO_H__
#define __USIO_H__

#include <linux/ioctl.h>
#include <linux/types.h>

struct usio_io {
	__u64 data;
	__u64 bytes;
	__u64 offset;
	__u32 flags;
	__u32 fd;
};

struct usio_ios {
	__u32 count;
	struct usio_io __user *__user *ios;
};

struct usio_event {
	__u64 io;
	__s64 res;
};

struct usio_events {
	__u32 min_count;
	__u32 max_count;
	struct usio_event __user *events;
};

#define USIO_IOC_MAGIC 'S'
#define USIO_SUBMIT  _IOW(USIO_IOC_MAGIC, 1, struct usio_ios)
#define USIO_RECLAIM _IOR(USIO_IOC_MAGIC, 2, struct usio_events)
#define USIO_IOC_MAXNR 2

#endif /*__SUIO_H__*/
