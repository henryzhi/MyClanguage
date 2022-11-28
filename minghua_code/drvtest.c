#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include "drv.h"

uint8_t g_buf[1024] = {1, 2, 3, 0};

static int load_drv() {
    int fd;
    fd = open("/dev/" DEV_NAME, O_RDWR);
    if (fd == -1) {
        perror("Failed to open /dev/" DEV_NAME);
    }
    return fd;
}

static void close_drv(int fd) {
    int e;
    e = close(fd);
    if (e == -1) {
        perror("Failed to close fd");
    }
}

static inline __attribute__((always_inline)) void clflushopt(virtaddr_t virt) {
    // asm volatile("clflushopt (%0)\n" ::"r"(virt)
    //              : "memory");
    asm volatile("clflush (%0)\n" ::"r"(virt) : "memory");  // ivy bridge
}
static inline __attribute__((always_inline)) void mfence() {
    asm volatile("mfence" ::
                     : "memory");
}

physaddr_t get_phys_addr(virtaddr_t virtual_addr) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    assert(fd >= 0);
    off_t pos = lseek(fd, (virtual_addr / PAGE_SIZE) * 8, SEEK_SET);
    assert(pos >= 0);
    uint64_t value;
    int got = read(fd, &value, 8);
    assert(got == 8);
    int rc = close(fd);
    assert(rc == 0);

    uint64_t frame_num = value & ((1ul << 54) - 1);
    uint64_t phys_addr = (frame_num * PAGE_SIZE) | (virtual_addr & (PAGE_SIZE - 1));

    return phys_addr;
}

/*
 * Reference:
 * Intel Software Developer's Manual Vol 3B "253669.pdf" August 2012
 * Intel Software Developer's Manual Vol 3C "326019.pdf" August 2012
 */
int main(void) {
    MsrInOut msr_struct = {0};

    // uint8_t g_buf[1024] = {1, 2, 3, 0};
    // volatile uint8_t* p = g_buf;
    // fprintf(stderr, "[+] p: %lx\n",(uint64_t)p);

    msr_struct.op = OP_PASS_PHYS;
    msr_struct.virt_addr_acc = (virtaddr_t)g_buf;
    msr_struct.phys_addr_acc = get_phys_addr((virtaddr_t)g_buf);

    int fd = load_drv();
    ioctl(fd, IOCTL_MSR_CMDS, (unsigned long)&msr_struct);
    close_drv(fd);

    fprintf(stderr, "start to hammer.\n");

    sleep(2);
    uint64_t N = 1; //1000000;
    for (uint64_t i = 0; i < N; ++i) {
      clflushopt((virtaddr_t)g_buf);
      *(volatile uint8_t*)g_buf = 0x5A;
    } 
    return 0;


    char c = 0;
    uint64_t sum = 0;
    uint64_t times = 0;

    // fprintf(stderr, "g_buf: %p\n", g_buf);
    // clflushopt((virtaddr_t)g_buf);

    // for (uint64_t i = 0; i < N; ++i) {
    // for (;;) {
    //     mfence();
    //     sum += *(volatile uint8_t*)g_buf;
    //     // clflushopt((virtaddr_t)g_buf);
    //     clflushopt((virtaddr_t)g_buf);

    //     c = getchar();
    //     fprintf(stderr, "c: %c\n", c);
    //     // sleep(1);
    // }

    sum += *(volatile uint8_t*)g_buf;
    clflushopt((virtaddr_t)g_buf);
    mfence();
    c = getchar();
    fprintf(stderr, "c: %hu, p: %p\n", c, g_buf);

    sum += *(volatile uint8_t*)g_buf;
    clflushopt((virtaddr_t)g_buf);
    mfence();
    c = getchar();
    fprintf(stderr, "c: %hu, p: %p\n", c, g_buf);

    sum += *(volatile uint8_t*)g_buf;
    clflushopt((virtaddr_t)g_buf);
    mfence();
    c = getchar();
    fprintf(stderr, "c: %hu, p: %p\n", c, g_buf);

    return 0;
}
