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
#include "sg_lib.h"
#include "sg_io_linux.h"


#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif  /* since /usr/include/scsi/sg.h doesn't know about this yet */

#define INQ_REPLY_LEN 96
#define INQ_CMD_LEN 6
#define TUR_CMD_LEN 6

#define EBUFF_SZ 256

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
    int sg_fd, k, ok;
    unsigned char inq_cdb[INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    unsigned char tur_cdb[TUR_CMD_LEN] =
                                {0x00, 0, 0, 0, 0, 0};
    unsigned char * inqBuff;
    unsigned char * inqBuff2;
    sg_io_hdr_t io_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char sense_buffer[32];
    int do_extra = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-x", argv[k], 2))
            do_extra = 1;
        else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else if (0 == file_name)
            file_name = argv[k];
        else {
            printf("too many arguments\n");
            file_name = 0;
            break;
        }
    }
    if (0 == file_name) {
        printf("Usage: 'sg_simple4 [-x] <sg_device>'\n");
        return 1;
    }

    /* N.B. An access mode of O_RDWR is required for some SCSI commands */
    if ((sg_fd = open(file_name, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "sg_simple4: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    /* Just to be safe, check we have a new sg device by trying an ioctl */
    if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30122)) {
        printf("sg_simple4: %s needs sg driver version >= 3.1.22\n",
               file_name);
        close(sg_fd);
        return 1;
    }

	//size_t res_sz = 96 * (1 << 10);
	//if (0 == (res_sz % 0x1000))
	//	res_sz = ((res_sz/0x1000) + 1) * 0x1000; 
    	//ioctl(sg_fd, SG_SET_RESERVED_SIZE, &res_sz);

	size_t res_sz = 4 * (1 << 20);
	if (0 == (res_sz % 0x1000))
		res_sz = ((res_sz/0x1000) + 1) * 0x1000;
	//res_sz = 0; 
    	if (ioctl(sg_fd, SG_SET_RESERVED_SIZE, &res_sz) < 0) {
		snprintf(ebuff, EBUFF_SZ, "sg_set_reserved_size: error using ioctl on "
			 "file: %s", file_name);
		perror(ebuff);
		return 1;
	}
	printf("max size:%zuKB.\n", res_sz >> 10);
	
    /* since I know this program will only read from inqBuff then I use
       PROT_READ rather than PROT_READ | PROT_WRITE */
    inqBuff = (unsigned char *)mmap(NULL, res_sz, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, sg_fd, 0);
    if (MAP_FAILED == inqBuff) {
        snprintf(ebuff, EBUFF_SZ, "sg_simple4: error using mmap() on "
                 "file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    
    //if (inqBuff[0])
    //    printf("non-null char at inqBuff[0]\n");
    //if (inqBuff[5000])
    //    printf("non-null char at inqBuff[5000]\n");

    /* Prepare INQUIRY command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inq_cdb);
    /* io_hdr.iovec_count = 0; */  /* memset takes care of this */
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = INQ_REPLY_LEN;
    /* io_hdr.dxferp = inqBuff; // ignored in mmap-ed IO */
    io_hdr.cmdp = inq_cdb;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    io_hdr.flags = SG_FLAG_MMAP_IO;
    /* io_hdr.pack_id = 0; */
    /* io_hdr.usr_ptr = NULL; */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_simple4: Inquiry SG_IO ioctl error");
        close(sg_fd);
        return 1;
    }


    /* Prepare TEST UNIT READY command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(tur_cdb);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.cmdp = tur_cdb;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_simple4: Test Unit Ready SG_IO ioctl error");
        close(sg_fd);
        return 1;
    }


    /* munmap(inqBuff, 8000); */
    /* could call munmap(inqBuff, INQ_REPLY_LEN) here but following close()
       causes this too happen anyway */
    inqBuff2 = (unsigned char *)mmap(NULL, res_sz, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, sg_fd, res_sz);
    if (MAP_FAILED == inqBuff2) {
        snprintf(ebuff, EBUFF_SZ, "sg_simple4: error using mmap() 2 on "
                 "file: %s", file_name);
        perror(ebuff);
        return 1;
    }


	 
	memset(inqBuff, 0, res_sz);
	memset(inqBuff2, 0, res_sz);

	for (int i = 0; i < res_sz; i+=0x1000) {
	    
		printf("buff virt addr:%lx, phys addr:%lx.\n", (uintptr_t)inqBuff + i, get_physical_addr((uintptr_t)inqBuff) + i);
		printf("buff2 virt addr:%lx, phys addr:%lx.\n", (uintptr_t)inqBuff2 + i, get_physical_addr((uintptr_t)inqBuff2) + i);

	}
 
    //if (inqBuff2[0])
    //    printf("non-null char at inqBuff2[0]\n");
    //if (inqBuff2[5000])
    //    printf("non-null char at inqBuff2[5000]\n");
    //{
    //    pid_t pid;
    //    pid = fork();
    //    if (pid) {
    //        inqBuff2[5000] = 33;
    //        munmap(inqBuff, 8000);
    //        sleep(3);
    //    }
    //    else {
    //        inqBuff[5000] = 0xaa;
    //        munmap(inqBuff, 8000);
    //        sleep(1);
    //    }
    //}
    
    close(sg_fd);
    return 0;
}
