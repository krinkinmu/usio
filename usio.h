#ifndef __USIO_H__
#define __USIO_H__

#include <linux/ioctl.h>
#include <linux/types.h>

struct usio_io {
	__u64 io_buffer;
	__u64 io_nbytes;
	__u64 io_offset;
	__u32 io_flags;
	__u32 io_filed;
};

#define USIO_IOC_MAGIC 'S'

#define USIO_SUBMIT    _IOW(USIO_IOC_MAGIC, 1, struct usio_io)
#define USIO_IOC_MAXNR 1

#endif /*__SUIO_H__*/
