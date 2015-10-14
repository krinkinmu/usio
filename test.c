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
#define BLOCK_SIZE     512
#define REQUESTS       (PAGE_SIZE / BLOCK_SIZE)

static char buffer[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

int main()
{
	struct usio_ios req;
	struct usio_io ios[REQUESTS], *ptrs[REQUESTS];
	struct usio_events rec;
	struct usio_event events[REQUESTS];

	int misc_fd, block_fd;
	int i, err = 0;

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

	req.count = REQUESTS;
	req.ios = ptrs;
	for (i = 0; i != REQUESTS; ++i) {
		ios[i].data = (__u64)(buffer + i * BLOCK_SIZE);
		ios[i].bytes = BLOCK_SIZE;
		ios[i].offset = i * BLOCK_SIZE;
		ios[i].flags = 1;
		ios[i].fd = block_fd;
		ptrs[i] = ios + i;
	}

	fprintf(stderr, "before USIO_SUBMIT\n");
	if ((i = ioctl(misc_fd, USIO_SUBMIT, &req)) != REQUESTS) {
		perror("submit failed");
		fprintf(stderr, "USIO_SUBMIT failed with %d, goto out\n", i);
		err = 1;
		goto out;
	}

	rec.min_count = REQUESTS;
	rec.max_count = REQUESTS;
	rec.events = events;
	fprintf(stderr, "before USIO_RECLAIM\n");
	if ((i = ioctl(misc_fd, USIO_RECLAIM, &rec)) != REQUESTS) {
		perror("reclaim failed");
		fprintf(stderr, "USIO_RECLAIM failed with %d, goto out\n", i);
		err = 1;
	}
out:
	close(misc_fd);
	close(block_fd);

	return err;
}
