#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include "usio.h"

#define MISC_DEV_NAME  "/dev/usio"
#define BLOCK_DEV_NAME "/dev/sdb"
#define PAGE_SIZE      4096

static char buffer[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

int main()
{
	int misc_fd, block_fd;
	struct usio_io io;
	int err = 0;

	misc_fd = open(MISC_DEV_NAME, O_RDWR);
	if (misc_fd == -1) {
		perror("Cannot open misc device file");
		exit(1);
	}

	block_fd = open(BLOCK_DEV_NAME, O_RDWR);
	if (block_fd == -1) {
		perror("Cannot open block device file");
		close(misc_fd);
		exit(1);
	}

	io.io_buffer = (__u64)buffer;
	io.io_nbytes = sizeof(buffer);
	io.io_offset = 0;
	io.io_flags = 0;
	io.io_filed = block_fd;

	if (ioctl(misc_fd, USIO_SUBMIT, &io) == -1) {
		perror("ioctl failed");
		err = 1;
	}

	close(misc_fd);
	close(block_fd);

	return err;
}
