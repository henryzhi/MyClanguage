/*
 * inline hook usage example.
 */

#define KMSG_COMPONENT "HELLO"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include "drv.h"

#include <asm/stacktrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>
#include <linux/stop_machine.h>
#include <linux/version.h>
#include <net/tcp.h>

#include "rh_trr.h"
#include "util.h"

physaddr_t g_phys_addr = 0;
virtaddr_t g_virt_addr = 0;
struct mm_struct* g_mm_watched = NULL;

physaddr_t g_pte_phys_page = 0;
virtaddr_t g_pte_virt_page = 0;
pmd_t* g_pmd_of_pte = NULL;

// spinlock_t g_pte_lock = __SPIN_LOCK_UNLOCKED();
DEFINE_SPINLOCK(g_pte_lock);

struct anon_vma_chain *(*my_anon_vma_interval_tree_iter_first)(struct rb_root * root, unsigned long start, unsigned long last);
struct anon_vma_chain *(*my_anon_vma_interval_tree_iter_next)(struct anon_vma_chain *node, unsigned long start, unsigned long last);
struct anon_vma *(*my_page_get_anon_vma)(struct page *page);
unsigned long (*my_vma_address)(struct page *page, struct vm_area_struct *vma);

pmd_t* (*my_mm_find_pmd)(struct mm_struct *mm, unsigned long address);

#define my_anon_vma_interval_tree_foreach(avc, root, start, last)       \
    for (avc = my_anon_vma_interval_tree_iter_first(root, start, last); \
         avc; avc = my_anon_vma_interval_tree_iter_next(avc, start, last))

/* variable */
static int (*handle_mm_fault_fn)(struct mm_struct *mm,
                                 struct vm_area_struct *vma,
                                 unsigned long address,
                                 unsigned int flags);

// static long (*sys_mkdir_fn)(const char __user *pathname, umode_t mode);
static void (*do_page_fault_fn)(struct pt_regs *regs, unsigned long error_code);
// static void hook_do_page_fault(struct pt_regs *regs, unsigned long error_code);

/* hook function */
static int hook_handle_mm_fault(struct mm_struct *mm,
                                struct vm_area_struct *vma,
                                unsigned long address,
                                unsigned int flags);
static void hook_do_page_fault(struct pt_regs *regs,
                                unsigned long error_code);

// static long hook_sys_mkdir(const char __user *pathname, umode_t mode);

static struct symbol_ops hello_ops[] = {
    DECLARE_SYMBOL(&do_page_fault_fn, "do_page_fault"),
    //DECLARE_SYMBOL(&handle_mm_fault_fn, "handle_mm_fault"),
    // DECLARE_SYMBOL(&sys_mkdir_fn, "sys_mkdir"),
};

static struct hook_ops hello_hooks[] = {
    DECLARE_HOOK(&do_page_fault_fn, hook_do_page_fault),
    //DECLARE_HOOK(&handle_mm_fault_fn, hook_handle_mm_fault),
    // DECLARE_HOOK(&sys_mkdir_fn, hook_sys_mkdir), test
};

/* hook function */
// static long hook_sys_mkdir(const char __user *pathname, umode_t mode) {
//     printk("[+] hook sys_mkdir\n");
//     return -1;
// }

// static void hook_do_page_fault(struct pt_regs *regs, unsigned long error_code) {
//     static uint64_t t = 0;
//     if (t++ % 1000000 == 0)
//         printk("[+] %s\n", __func__);
//     return do_page_fault_fn(regs, error_code);
// }


void __clflush(void* p) {
    asm volatile("clflushopt (%0)"
                 :
                 : "r"(p)
                 : "memory");
}

pmd_t *__mm_find_pmd(struct mm_struct *mm, unsigned long address) {
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd = NULL;
    pmd_t pmde;
    if (mm == NULL) {
        printk(" %s. mm\n", __func__);
        goto out;
    }

    pgd = pgd_offset(mm, address);
    if (!pgd_present(*pgd)) {
        printk(" %s. pgd\n", __func__);
        goto out;
    }

    pud = pud_offset(pgd, address);
    if (!pud_present(*pud)) {
        printk(" %s. pud\n", __func__);
        goto out;
    }

    pmd = pmd_offset(pud, address);
    /*
	 * Some THP functions use the sequence pmdp_huge_clear_flush(), set_pmd_at()
	 * without holding anon_vma lock for write.  So when looking for a
	 * genuine pmde (in which to find pte), test present and !THP together.
	 */
    pmde = *pmd;
    barrier();
    if (!pmd_present(pmde) || pmd_trans_huge(pmde)) {
        printk(" %s. pmd_present: %d\n", __func__, pmd_present(pmde));
        printk(" %s. pmd_trans_huge: %d\n", __func__, pmd_trans_huge(pmde));
        pmd = NULL;
    }
out:
    return pmd;
}

// void set_pte_x_bit(struct mm_struct* mm, virtaddr_t address) {
bool set_pte_x_bit(struct mm_struct *mm, virtaddr_t address) {
    bool ret = true;
    printk("[+] %s start.\n", __func__);
    pmd_t *pmd = __mm_find_pmd(mm, address);
    if (!pmd) {
        printk("[-] pmd: %lx\n", pmd);
        ret = false;
        goto __set_pte_x_bit_ret;
    }
    printk("[+] before set r/w flag of pmd: %lx, pmd->pmd: %lx\n", pmd, pmd->pmd);
    // set pte present to 1
    spinlock_t *ptl = NULL;
    pte_t* pte = pte_offset_map_lock(mm, pmd, address, &ptl);
    if (pte) {
        printk("[+] before set r/w flag of pte: %lx, pte->pte: %lx\n", pte, pte->pte);
        // pte->pte = pte->pte | _PAGE_PRESENT;
        // printk("[+] set present flag of pte->pte: %lx, present: %d\n", pte->pte, pte_present(*pte));
        set_pte(pte, pte_mkwrite(*pte)); // set r/w
        printk("[+] after set r/w flag of pte: %p, pte->pte: %lx, r/w: %d\n", pte, pte->pte, pte_write(*pte) != 0);

        // set_pte(pte, pte_mkyoung(*pte)); // set access bit 

        pte_unmap_unlock(pte, ptl);
    } else {
        printk("[+] pte is null.\n\n");
    }

__set_pte_x_bit_ret:
    printk("[+] %s end.\n", __func__);
    return ret;
}

void clear_pte_x_bit(struct mm_struct* mm, virtaddr_t address) {
    printk("[+] %s start.\n", __func__);
    pmd_t *pmd = __mm_find_pmd(mm, address); 
    if (!pmd) {
        goto __clear_pte_x_bit_ret;
    }

    spinlock_t *ptl = NULL;
    pte_t* pte = pte_offset_map_lock(mm, pmd, address, &ptl);
    // pte->pte = pte->pte & ~_PAGE_PRESENT;
    // printk("[+] clear present flag of pte->pte: %lx, present: %d\n", pte->pte, pte_present(*pte));
    printk("[+] before clear r/w flag of pte: %p, pte->pte: %lx\n", pte, pte->pte);
    set_pte(pte, pte_wrprotect(*pte));  // clear r/w
    printk("[+] clear r/w flag of pte: %p. pte->pte: %lx, r/w: %d\n", pte, pte->pte, pte_write(*pte) != 0);
    pte_unmap_unlock(pte, ptl);

__clear_pte_x_bit_ret:
    printk("[+] %s end.\n", __func__);
    return;
}


bool set_pmd_x_bit(struct mm_struct *mm, virtaddr_t address) {
    printk("[+] %s start.\n", __func__);
    bool ret = true;
    pmd_t *pmd = __mm_find_pmd(mm, address);  
    if (!pmd) {
        ret = false; 
        goto __set_pmd_x_bit_ret;
    }

    spinlock_t *ptl = pmd_lockptr(mm, pmd);
    // pmd->pmd = pmd->pmd | _PAGE_PRESENT;
    // printk("[+] set present flag of pmd->pmd: %lx, present: %d\n\n", pmd->pmd, pmd_present(*pmd));
    set_pmd(pmd, pmd_mkwrite(*pmd));
    printk("[+] set r/w flag of pmd: %p, pmd->pmd: %lx, r/w: %d\n", pmd, pmd->pmd, pmd_present(*pmd) != 0);

    // set_pmd(pmd, pmd_mkyoung(*pmd));  // set access bit

    spin_unlock(ptl);

__set_pmd_x_bit_ret:
    printk("[+] %s end.\n", __func__);
    return ret;
}

void clear_pmd_x_bit(struct mm_struct *mm, virtaddr_t address) {
    printk("[+] %s start.\n", __func__);
    pmd_t *pmd = __mm_find_pmd(mm, address); 
    if (!pmd) {
        goto __clear_pmd_x_bit_ret;
    }

    spinlock_t *ptl = pmd_lockptr(mm, pmd);
    printk("[+] before clear r/w flag of pmd: %p, pmd->pmd: %lx\n", pmd, pmd->pmd);
    // pmd->pmd = pmd->pmd & ~_PAGE_PRESENT;
    // printk("[+] clear present flag of pmd->pmd: %lx, present: %d\n\n", pmd->pmd, pmd_present(*pmd));
    set_pmd(pmd, pmd_wrprotect(*pmd));
    printk("[+] after clear r/w flag of pmd: %p. pmd->pmd: %lx, r/w: %d\n", pmd, pmd->pmd, pmd_write(*pmd) != 0);
    spin_unlock(ptl);

__clear_pmd_x_bit_ret:
    printk("[+] %s end.\n", __func__);
    return;
}

virtaddr_t __virt_page(virtaddr_t vaddr) {
    return vaddr >> PAGE_SHIFT;
}

static void hook_do_page_fault(struct pt_regs *regs, unsigned long error_code) {
    
    unsigned long address = read_cr2();
    struct task_struct *tsk = current;
    struct mm_struct *mm = tsk->mm; 
    bool watched = false;
    int ret = 0;
    physaddr_t phys = 0;
    proc_info_t proc_info = {0};
    get_proc_by_mm(mm, &proc_info);
    if (strcmp(proc_info.proc_name, "drvtest") != 0) {
        watched = false;
    }
    
    // pte page
    if (__virt_page(address) == __virt_page(g_pte_virt_page)) {
        printk("\n[+] --- %s. Got pmd. address; %lx\n\n", __func__, address);

        pmd_t *pmd = __mm_find_pmd(mm, address);
        if (!pmd) {
            printk("[-] %s. pte page. pmd is null. goto __pass.\n", __func__);
            goto __pass;
        }

        if (pmd_none(*pmd)) {
            printk("[-] %s. pte page. pmd is none. pmd: %p\n", pmd);
            goto __pass;
        }

        if (pmd != g_pmd_of_pte) {
            printk("[-] %s. pte page. pmd is not the watched one. goto __pass.\n", __func__);
            goto __pass;
        }

        printk("[+] ---- got g_pmd_of_pte. ---\n");

        if (set_pmd_x_bit(mm, address) == false) {
            goto __pass;
        }

        //set_pte_x_bit(mm, address);

        return;
    }
    
    // data page
    if (__virt_page(address) == __virt_page(g_virt_addr)) {
        printk("\n[+] !!! %s. access the virt page. address: %lx\n\n", __func__, address);

        pmd_t *pmd = __mm_find_pmd(mm, address);
        // have not create page table entry yet
        if (!pmd) {
            printk("[-] %s. data page. pmd is null. goto __pass.\n", __func__);
            goto __pass;
        }
        
        if (set_pte_x_bit(mm, address) == false) {
            goto __pass;
        }

        clear_pmd_x_bit(mm, address);
        return;
    }

__pass:
    do_page_fault_fn(regs, error_code);
    return;
}

// 第一次拦截到被监控的地址，应该放掉。因为它可能是第一次被访问，还没有建立pgd/pud/pmd/pte/pagetable映射。应该让page fault来为它建立。
static int hook_handle_mm_fault(struct mm_struct *mm,
                                struct vm_area_struct *vma,
                                unsigned long address,
                                unsigned int flags) {
    //printk("[+] hook_handle_mm_fault\n");
    bool watched = false;
    int ret = 0;
    physaddr_t phys = 0;
    proc_info_t proc_info = {0};
    get_proc_by_mm(mm, &proc_info);
    if (strcmp(proc_info.proc_name, "drvtest") != 0) {
        watched = false;
    }

   // printk("[+] %s. address: %lx\n", __func__, address);  
    if (watched) {
        pte_t* pte = ptwalk(mm, address, &phys);
        if (pte) {
            printk("[+]  address: %lx, phys: %lx, r/w in pte flag: %d\n", address, phys, pte_write(*pte)!=0);
        }
    }

    // pte page
    if (__virt_page(address) == __virt_page(g_pte_virt_page)) {
        printk("\n[+] --- %s. Got pmd. address; %lx\n\n", __func__, address);

        pmd_t *pmd = __mm_find_pmd(mm, address);
        if (!pmd) {
            printk("[-] %s. pte page. pmd is null. goto __pass.\n", __func__);
            goto __pass;
        }

        if (pmd_none(*pmd)) {
            printk("[-] %s. pte page. pmd is none. pmd: %p\n", pmd);
            goto __pass;
        }

        if (pmd != g_pmd_of_pte) {
            printk("[-] %s. pte page. pmd is not the watched one. goto __pass.\n", __func__);
            goto __pass;
        }

        printk("[+] ---- got g_pmd_of_pte. ---\n");

        if (set_pmd_x_bit(mm, address) == false) {
            goto __pass;
        }

        clear_pte_x_bit(mm, address);

        return 0;
    }

    // data page
    if (__virt_page(address) == __virt_page(g_virt_addr)) {
        printk("\n[+] !!! %s. access the virt page. address: %lx\n\n", __func__, address);

        pmd_t *pmd = __mm_find_pmd(mm, address);
        // have not create page table entry yet
        if (!pmd) {
            printk("[-] %s. data page. pmd is null. goto __pass.\n", __func__);
            goto __pass;
        }
        
        if (set_pte_x_bit(mm, address) == false) {
            goto __pass;
        }

        clear_pmd_x_bit(mm, address);

        return ret;
    }

__pass:
    ret = handle_mm_fault_fn(mm, vma, address, flags);
    if (watched) {
        pte_t *pte = ptwalk(mm, address, &phys);
        if (pte)
            printk("[+] check again. address: %lx, phys: %lx, r/w in pte flag: %d. access bit: %d\n", 
            address, phys, pte_write(*pte) != 0, pte_young(*pte));
    }

    return ret;
}

#if defined(timer_solution)
static int hook_handle_mm_fault(struct mm_struct *mm,
                                struct vm_area_struct *vma,
                                unsigned long address,
                                unsigned int flags) {
    //printk("[+] hook_handle_mm_fault\n");
    bool watched = false;
    int ret = 0;
    pte_t* pte = NULL;
    physaddr_t phys = 0;
    proc_info_t proc_info = {0};
    get_proc_by_mm(mm, &proc_info);
    if (strcmp(proc_info.proc_name, "drvtest") != 0) {
        watched = false;
    }

    spin_lock(&g_pte_lock);

    // printk("[+] %s. address: %lx\n", __func__, address);
    if (watched) {
        pte = ptwalk(mm, address, &phys);
        if (pte) {
            printk("[+]  address: %lx, phys: %lx, r/w in pte flag: %d\n", address, phys, pte_write(*pte) != 0);
        }
    }

    // data page
    if (__virt_page(address) == __virt_page(g_virt_addr)) {
        printk("\n[+] !!! %s. access the virt page. address: %lx\n\n", __func__, address);

        pmd_t *pmd = __mm_find_pmd(mm, address);
        // have not create page table entry yet
        if (!pmd) {
            printk("[-] %s. data page. pmd is null. goto __pass.\n", __func__);
            goto __pass;
        }

        if (set_pte_x_bit(mm, address) == false) {
            goto __pass;
        }

        // clear_pmd_x_bit(mm, address);
        spin_unlock(&g_pte_lock);
        return 0;
    }

__pass:
    ret = handle_mm_fault_fn(mm, vma, address, flags);
    if (watched) {
        if (pte = ptwalk(mm, address, &phys)) {
            printk("[+] check again. address: %lx, phys: %lx, r/w in pte flag: %d. access bit: %d\n",
                   address, phys, pte_write(*pte) != 0, pte_young(*pte));
        }
    }
    
    spin_unlock(&g_pte_lock);

    return ret;
}
#endif

// pmd_t* __pmd_offset(struct mm_struct* mm, virtaddr_t vaddr) {
//     pgd_t* pgd = pgd_offset(current->mm, addr);
//     if (unlikely(pgd_none(*pgd) || pgd_bad(*pgd))) {
//         printk("[-] %s. pgd --\n", __func__);
//         return 0;
//     }

//     pud_t* pud = pud_offset(pgd, addr);
//     if (unlikely(pud_none(*pud) || pud_bad(*pud))) {
//         printk("[-] %s. pud --\n", __func__);
//         return 0;
//     }

//     pmd_t* pmd = pmd_offset(pud, addr);
//     return pmd;
// }

static long msrdrv_ioctl(struct file *f, unsigned int ioctl_num, unsigned long ioctl_param) {
    if (ioctl_num != IOCTL_MSR_CMDS) {
        return 0;
    }

    printk("[+] ioctl called\n");
    
    struct MsrInOut* msrops = (struct MsrInOut *)ioctl_param;
    // assert(msrops);

    if (msrops->op == OP_PASS_PHYS) {
        g_phys_addr = msrops->phys_addr_acc;
        g_virt_addr = msrops->virt_addr_acc;
        printk("[+] R3 virt accessed: %lx, phys accessed: %lx\n", g_virt_addr, g_phys_addr);

        struct page* page = pfn_to_page(g_phys_addr >> PAGE_SHIFT);
        if (page == NULL) {
            printk("[-] page is NULL. g_phys_addr: %lx, g_virt_addr: %lx\n", g_phys_addr, g_virt_addr);
            return -1;
        }
        struct anon_vma* av = my_page_get_anon_vma(page);
        struct anon_vma_chain *vmac = NULL;
        struct vm_area_struct *vma = NULL;
        virtaddr_t vaddr = 0;
        physaddr_t phys = 0;
        // pgoff_t pgoff = page_to_pgoff(page);
        // printk("[+] pgoff: %lx\n", pgoff);
        if (av) {
            anon_vma_lock_read(av);
            my_anon_vma_interval_tree_foreach(vmac, &av->rb_root, 0, ULONG_MAX) {  // start, end ?
                vma = vmac->vma;
                vaddr = my_vma_address(page, vma);
                pte_t* pte = ptwalk(vma->vm_mm, vaddr, &phys);
                if (pte == NULL) {
                    continue;
                }

                proc_info_t proc_info = {0};
                get_proc_by_mm(vma->vm_mm, &proc_info);
                // printk("[+] vaddr: %lx (check same). pte->pte: %lx, present: %d, pid: %d, proc: %s\n", 
                //     vaddr, pte->pte, pte_present(*pte), proc_info.pid, proc_info.proc_name);
                printk("[+] vaddr: %lx. pte->pte: %lx, r/w: %d, pid: %d, proc: %s\n",
                       vaddr, pte->pte, pte_write(*pte)!=0, proc_info.pid, proc_info.proc_name);

                // pmd
                pmd_t *pmd = __mm_find_pmd(vma->vm_mm, vaddr);  //my_mm_find_pmd(vma->vm_mm, vaddr);
                if (pmd) {
                    printk("[+] pmd: %lx, pmd->pmd: %lx\n", pmd, pmd->pmd);
                } else {
                    printk("[+] pmd is null\n");
                }

                //page = pmd_page(*pmd);  // return struct page* 
                g_pte_virt_page = pmd_page_vaddr(*pmd); // pmd 中编码的pfn对应的virt page addr
                g_pte_phys_page = pmd_pfn(*pmd) << PAGE_SHIFT;
                g_pmd_of_pte = pmd; // __mm_find_pmd(vma->vm_mm, vaddr);
                if (g_mm_watched != NULL && g_mm_watched != vma->vm_mm) {
                    printk("[+] interesting. g_mm_watched previous value does NOT equal vma->vm_mm\n");
                }
                g_mm_watched = vma->vm_mm;

                printk("[+] g_pte_virt_page: %lx, g_pte_phys_page: %lx, g_pmd_of_pte: %lx\n", g_pte_virt_page, g_pte_phys_page, g_pmd_of_pte);
                
                clear_pte_x_bit(vma->vm_mm, vaddr);
                
                // __clflush((void*)vaddr);

            }
            anon_vma_unlock_read(av);
        }
    }
    
    printk("[+] ioctl return\n");

    return 0;
}


/*
spinlock_t* ptl;
pmd_t* pmd = mm_find_pmd(mm, addr)
pte_t* pte = pte_offset_map_lock(mm, pmd, addr, &ptl)
pte_clear_flags(*pte, _PAGE_PRESENT);
pte_unmap_unlock(pte, ptl)
*/

static int msrdrv_open(struct inode *i, struct file *f) {
    return 0;
}

static int msrdrv_release(struct inode *i, struct file *f) {
    return 0;
}

static ssize_t msrdrv_read(struct file *f, char *b, size_t c, loff_t *o) {
    return 0;
}

static ssize_t msrdrv_write(struct file *f, const char *b, size_t c, loff_t *o) {
    return 0;
}

dev_t msrdrv_dev;
struct cdev *msrdrv_cdev;

struct file_operations msrdrv_fops = {
    .owner = THIS_MODULE,
    .read = msrdrv_read,
    .write = msrdrv_write,
    .open = msrdrv_open,
    .release = msrdrv_release,
    .unlocked_ioctl = msrdrv_ioctl,
    .compat_ioctl = NULL,
};

static int resolve_symbols(void ) {
    my_vma_address = (unsigned long *)kallsyms_lookup_name("vma_address");
    my_anon_vma_interval_tree_iter_first = (struct anon_vma_chain *)kallsyms_lookup_name("anon_vma_interval_tree_iter_first");
    my_anon_vma_interval_tree_iter_next = (struct anon_vma_chain *)kallsyms_lookup_name("anon_vma_interval_tree_iter_next");
    my_page_get_anon_vma = (struct anon_vma *)kallsyms_lookup_name("page_get_anon_vma");
    my_mm_find_pmd = (pmd_t*)kallsyms_lookup_name("mm_find_pmd");

    printk("[+] my_vma_address: %lx\n", my_vma_address);
    printk("[+] my_anon_vma_interval_tree_iter_first: %lx\n", my_anon_vma_interval_tree_iter_first);
    printk("[+] my_anon_vma_interval_tree_iter_next: %lx\n", my_anon_vma_interval_tree_iter_next);
    printk("[+] my_page_get_anon_vma: %lx\n", my_page_get_anon_vma);
    printk("[+] my_mm_find_pmd: %lx\n", my_mm_find_pmd);

    if (my_mm_find_pmd && my_anon_vma_interval_tree_iter_first && my_anon_vma_interval_tree_iter_next && my_page_get_anon_vma && my_vma_address) {
        return 0;
    }
    return -1;
}

static struct hrtimer timer;
ktime_t hr_kt;
int g_nano_sec = 1 * 1000 / 10; //2 * 1000 * 1000;  // ms * us * ns
#define REFRESH_TIME 100

static enum hrtimer_restart hrtimer_handler(struct hrtimer *timer) {

    // next expire time
    hr_kt = ktime_set(0, g_nano_sec);
    hrtimer_forward_now(timer, hr_kt);

    static uint64_t t = 0;
    if (++t % 1000000 == 0) {
        printk("[+] %s. clear_pte_x_bit periodically.\n", __func__);
   
        ///
        spin_lock(&g_pte_lock);
        if (g_mm_watched && g_virt_addr) {
            clear_pte_x_bit(g_mm_watched, g_virt_addr);
            __clflush((void*)g_virt_addr);
        }
        spin_unlock(&g_pte_lock);
        ///
    }

    return HRTIMER_RESTART;
}

static void my_hrtimer_init(void) {
    hr_kt = ktime_set(0, g_nano_sec);
    hrtimer_init(&timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    hrtimer_start(&timer, hr_kt, HRTIMER_MODE_REL);
    timer.function = hrtimer_handler;
}

static void my_hrtimer_exit(void) {
    hrtimer_cancel(&timer);
}

static int __init hello_init(void)
{
    if (0 != resolve_symbols()) {
        return -1;
    }

    msrdrv_dev = MKDEV(DEV_MAJOR, DEV_MINOR);
    register_chrdev_region(msrdrv_dev, 1, DEV_NAME);
    msrdrv_cdev = cdev_alloc();
    msrdrv_cdev->owner = THIS_MODULE;
    msrdrv_cdev->ops = &msrdrv_fops;
    cdev_init(msrdrv_cdev, &msrdrv_fops);
    cdev_add(msrdrv_cdev, msrdrv_dev, 1);
    printk(KERN_ALERT "Module " DEV_NAME " loaded\n");

    /// setup hooks
    if (!find_ksymbol(hello_ops, ARRAY_SIZE(hello_ops))) {
        pr_err("hello symbol table not find.\n");
        return -1;
    }

    if (!inl_sethook_ops(hello_hooks, ARRAY_SIZE(hello_hooks))) {
        pr_err("hijack hello functions fail.\n");
        return -1;
    }
    ///

    //my_hrtimer_init();

    pr_info("hello loaded.\n");

	return 0;
}


static void __exit hello_cleanup(void)
{
	inl_unhook_ops(hello_hooks, ARRAY_SIZE(hello_hooks));

    cdev_del(msrdrv_cdev);
	unregister_chrdev_region(msrdrv_dev, 1);

    // my_hrtimer_exit();
	
    pr_info("hello unloaded.\n");
}


module_init(hello_init);
module_exit(hello_cleanup);
MODULE_LICENSE("GPL");
