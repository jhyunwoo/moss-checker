#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include "mem_ioctl.h"

#define PROCFS_NAME "malloc_monitor"
#define STUDENT_ID "2024148005"
#define STUDENT_NAME "JEON Hyunwoo"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JEON Hyunwoo");
MODULE_DESCRIPTION("Memory Allocation Monitor for SP Assignment 2");

// Data structure to store history
struct monitor_entry {
    struct list_head list;
    int pid;
    char type[10]; // "MALLOC", "ACCESS", "KMALLOC"
    unsigned long target_value;
    
    // Page Table Infos
    unsigned long pgd_address, pgd_value;
    unsigned long pud_address, pud_value;
    unsigned long pmd_address, pmd_value;
    unsigned long pte_address, pte_value;
    unsigned long final_pa;
    
    // Flags to indicate which levels exist
    int has_pgd;
    int has_pud;
    int has_pmd;
    int has_pte;
    int has_pa;
};

static LIST_HEAD(history_list);
static DEFINE_SPINLOCK(history_lock);

static long monitor_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int monitor_show(struct seq_file *m, void *v);
static int monitor_open(struct inode *inode, struct file *file);

static const struct proc_ops monitor_fops = {
    .proc_open = monitor_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_ioctl = monitor_ioctl,
};

// History persists until module removal (rmmod) as per assignment requirements.
// Memory usage is not a concern for the scope of this assignment.
static void clear_history(void) {
    struct monitor_entry *tmp, *entry;
    spin_lock(&history_lock);
    list_for_each_entry_safe(entry, tmp, &history_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&history_lock);
}

static int __init init_monitor(void) {
    struct proc_dir_entry *entry;
    entry = proc_create(PROCFS_NAME, 0666, NULL, &monitor_fops);
    if (!entry) {
        return -ENOMEM;
    }
    return 0;
}

static void __exit exit_monitor(void) {
    remove_proc_entry(PROCFS_NAME, NULL);
    clear_history();
}

static int monitor_open(struct inode *inode, struct file *file) {
    return single_open(file, monitor_show, NULL);
}

static int monitor_show(struct seq_file *m, void *v) {
    struct monitor_entry *entry;
    int count = 1;

    seq_printf(m, "ID: %s\n", STUDENT_ID);
    seq_printf(m, "Name: %s\n\n", STUDENT_NAME);
    seq_printf(m, "============================================================\n");

    spin_lock(&history_lock);
    list_for_each_entry(entry, &history_list, list) {
        seq_printf(m, "[%d] PID: %d | Type: %s\n", count++, entry->pid, entry->type);
        seq_printf(m, "------------------------------------------------------------\n");
        seq_printf(m, "Target VA : 0x%lx\n", entry->target_value);

        if (strcmp(entry->type, "KMALLOC") == 0) {
            seq_printf(m, "Final PA : 0x%lx\n", entry->final_pa);
        } else {
            seq_printf(m, "PGD : Addr = 0x%lx, Val = 0x%lx\n", entry->pgd_address, entry->pgd_value);
            seq_printf(m, "PUD : Addr = 0x%lx, Val = 0x%lx\n", entry->pud_address, entry->pud_value);
            seq_printf(m, "PMD : Addr = 0x%lx, Val = 0x%lx\n", entry->pmd_address, entry->pmd_value);
            seq_printf(m, "PTE : Addr = 0x%lx, Val = 0x%lx\n", entry->pte_address, entry->pte_value);
            
            if (entry->has_pa)
                seq_printf(m, "Final PA : 0x%lx\n", entry->final_pa);
            else
                seq_printf(m, "Final PA : (Not Mapped)\n");
        }
        seq_printf(m, "============================================================\n");
    }
    spin_unlock(&history_lock);

    return 0;
}

static void walk_user_page_table(unsigned long va, struct monitor_entry *entry) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct mm_struct *mm = current->mm;

    if (!mm) {
        return;
    }
    mmap_read_lock(mm);

    pgd = pgd_offset(mm, va);
    entry->pgd_address = (unsigned long)pgd;
    entry->pgd_value = pgd_value(*pgd);
    entry->has_pgd = 1;

    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        goto out;
    }

    p4d = p4d_offset(pgd, va);
 
    pud = pud_offset(p4d, va);
    entry->pud_address = (unsigned long)pud;
    entry->pud_value = pud_value(*pud);
    entry->has_pud = 1;

    if (pud_none(*pud) || pud_bad(*pud)) {
        goto out;
    }

    pmd = pmd_offset(pud, va);
    entry->pmd_address = (unsigned long)pmd;
    entry->pmd_value = pmd_value(*pmd);
    entry->has_pmd = 1;

    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        goto out;
    }

    pte = pte_offset_kernel(pmd, va);
    if (!pte) {
        goto out;
    }

    entry->pte_address = (unsigned long)pte;
    entry->pte_value = pte_value(*pte);
    entry->has_pte = 1;

    if (pte_present(*pte)) {
        entry->final_pa = (pte_pfn(*pte) << PAGE_SHIFT) | (va & ~PAGE_MASK);
        entry->has_pa = 1;
    }

out:
    mmap_read_unlock(mm);
}

static long monitor_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct monitor_entry *entry;
    void *kptr;

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }
    memset(entry, 0, sizeof(*entry));
    entry->pid = current->pid;

    switch (cmd) {
        case CMD_MALLOC:
            strcpy(entry->type, "MALLOC");
            entry->target_value = arg;
            walk_user_page_table(entry->target_value, entry);
            break;

        case CMD_ACCESS:
            strcpy(entry->type, "ACCESS");
            entry->target_value = arg;
            walk_user_page_table(entry->target_value, entry);
            break;

        case CMD_KMALLOC:
            strcpy(entry->type, "KMALLOC");
            kptr = kmalloc(4096, GFP_KERNEL);
            if (kptr) {
                entry->target_value = (unsigned long)kptr;
                entry->final_pa = virt_to_phys(kptr);
                entry->has_pa = 1;
                kfree(kptr);
            }
            break;

        default:
            kfree(entry);
            return -EINVAL;
    }

    spin_lock(&history_lock);
    list_add_tail(&entry->list, &history_list);
    spin_unlock(&history_lock);

    return 0;
}

module_init(init_monitor);
module_exit(exit_monitor);

