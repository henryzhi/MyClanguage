#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>
#include <stdint.h>

// Extract the physical page number from a Linux /proc/PID/pagemap entry.
uint64_t frame_number_from_pagemap(uint64_t value) {
	return value & ((1ULL << 54) - 1);
}
uint64_t get_physical_addr(uintptr_t virtual_addr) {
	const size_t page_size = 0x1000;
	int fd = open("/proc/self/pagemap", O_RDONLY);
	assert(fd >= 0);

	off_t pos = lseek(fd, (virtual_addr / page_size) * 8, SEEK_SET);
	assert(pos >= 0);
	uint64_t value;
	int got = read(fd, &value, 8);
	assert(got == 8);
	int rc = close(fd);
	assert(rc == 0);

	// Check the "page present" flag.
	//assert(value & (1ULL << 63));

	uint64_t frame_num = frame_number_from_pagemap(value);
	return (frame_num * page_size) | (virtual_addr & (page_size - 1));
}

int main(int argc, char * argv[])
{
	int kmsg_fd, k, ok;
	unsigned char * inqBuff;

	/* N.B. An access mode of O_RDWR is required for some SCSI commands */
	if ((kmsg_fd = open("/dev/net/tun", O_RDWR)) < 0) {
		printf("open error.\n");
		return 1;
	}

	int real_sz = 1 << 20;
	
	inqBuff = (unsigned char *)mmap(NULL, real_sz, PROT_READ|PROT_WRITE,
		MAP_SHARED, kmsg_fd, 0);
	if (MAP_FAILED == inqBuff) {
		printf("mmap error.\n");
		return 1;
	}
    
	for (int i = 0; i < real_sz; i+=0x8000) {
		printf("buff virt addr:%lx, phys addr:%lx.\n", (uintptr_t)inqBuff + i, get_physical_addr((uintptr_t)inqBuff) + i);
	}
 
	close(kmsg_fd);
	return 0;
}
