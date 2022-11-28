
#include <asm/atomic.h>
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include "comm.h"

typedef struct _proc_info {
    unsigned long pid;
    char proc_name[256];
} proc_info_t;

pte_t *ptwalk(struct mm_struct *mm, virtaddr_t address, physaddr_t* p_phys);
void get_proc_by_mm(struct mm_struct *mm, proc_info_t* proc_info);
