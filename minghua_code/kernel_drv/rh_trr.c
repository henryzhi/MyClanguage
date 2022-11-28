#include "rh_trr.h"

pte_t *ptwalk(struct mm_struct *mm, virtaddr_t address, physaddr_t* p_phys) {
    pgd_t *pgd;
    pte_t *ptep;
    pud_t *pud;
    pmd_t *pmd;
    unsigned long addr = address;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        printk(" 1 \n");
        goto out;
    }
    // printk(KERN_NOTICE "Valid pgd");

    pud = pud_offset(pgd, addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        printk(" 2 \n");
        goto out;
    }
    // printk(KERN_NOTICE "Valid pud");

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        printk(" 3 \n");
        goto out;
    }
    // printk(KERN_NOTICE "Valid pmd");

    // *ptephy = (pmd_pfn(*pmd) << 12) + pte_index(address) * 8;

    ptep = pte_offset_kernel(pmd, addr);  //pte_offset_map(pmd, addr);
    if (!ptep) {
        printk(" 4 \n");
        goto out;
    }

    // if (pte_none(*pte)) {} 

    // addr = ptep->pte;

    // printk("pte_pfn(*ptep): %lx\n", pte_pfn(*ptep));

    *p_phys = (pte_pfn(*ptep) << PAGE_SHIFT) + (address & 0xfff);

    return ptep;

out:
    return 0;
}

void get_proc_by_mm(struct mm_struct *mm, proc_info_t* proc_info) {
    struct task_struct *task = &init_task;
    for_each_process(task) {
        if (task->mm == mm) {
            proc_info->pid = task->pid;
            strcpy(proc_info->proc_name, task->comm);
            break;
            // printk("[+] mm: %lx, pid: %d, proc: %s\n", mm, task->pid, task->comm);
        }
    }
}
