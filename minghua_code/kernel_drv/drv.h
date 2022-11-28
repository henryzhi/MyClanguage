#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/types.h>

#include "comm.h"

#define DEV_NAME "software-trr"
#define DEV_MAJOR 223
#define DEV_MINOR 0

#define MSR_VEC_LIMIT 32

#define IOCTL_MSR_CMDS _IO(DEV_MAJOR, 1)

enum MsrOperation {
    OP_PASS_PHYS = 0, 
    // MSR_NOP = 0,
    // MSR_READ = 1,
    // MSR_WRITE = 2,
    // MSR_STOP = 3,
    // MSR_RDTSC = 4
};

// struct MsrInOut {
//     unsigned int op;          // MsrOperation
//     unsigned long boolvalue;  // msr identifier
//     unsigned long addr;       // quad word
// };                            // msrdrv.h:27:1: warning: packed attribute is unnecessary for ‘MsrInOut’ [-Wpacked

typedef struct MsrInOut {
    unsigned int op;
    virtaddr_t virt_addr_acc;
    physaddr_t phys_addr_acc;
} MsrInOut;