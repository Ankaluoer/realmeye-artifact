// f3_target.c
// A-1 test-stimulus module for RealmEye F3 (stage-2 write-trap) validation.
//
// What it does (and deliberately does NOT do):
//   * Allocates ONE private page with vmalloc(). This page is writable at
//     stage-1 by nature, so NO kernel write-protection is touched or bypassed.
//   * Prints the page's kernel VA so you can convert it to an IPA with your
//     already-verified cmd 2 (READ_VA).
//   * Exposes /proc/f3_trigger. Writing to it makes the module perform ONE
//     store to the target page -- that store is the stimulus that fires your
//     RMM stage-2 trap set via cmd 4.
//
// This is a detector-validation harness: it pokes YOUR OWN monitor to prove
// the trap fires. It is not a rootkit and hides nothing.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define F3_TAG "f3_target"

static void *target_page;        // vmalloc'd target
static struct proc_dir_entry *proc_entry;
static volatile unsigned long *target_word;  // where we store

// Perform the single write that should trip the stage-2 trap.
static void f3_do_write(void)
{
    unsigned long old, val;

    old = *target_word;
    val = old + 1;               // change the value so the store is real
    *target_word = val;          // <-- THE STIMULUS: stage-2 trap should fire here

    // Barrier so the store is not reordered/elided before we log.
    smp_wmb();

    pr_err(F3_TAG ": WROTE target va=%px old=0x%lx new=0x%lx\n",
           (void *)target_word, old, *target_word);
}

static ssize_t f3_proc_write(struct file *f, const char __user *buf,
                             size_t len, loff_t *off)
{
    pr_err(F3_TAG ": /proc/f3_trigger written -> issuing one store\n");
    f3_do_write();
    return len;   // consume all input
}

// Also let `cat /proc/f3_trigger` reprint the VA + PA hints.
static ssize_t f3_proc_read(struct file *f, char __user *buf,
                            size_t len, loff_t *off)
{
    char line[160];
    struct page *pg;
    phys_addr_t pa = 0;
    int n;

    if (*off > 0)
        return 0;

    pg = vmalloc_to_page((void *)target_word);
    if (pg)
        pa = page_to_phys(pg) + offset_in_page((void *)target_word);

    n = scnprintf(line, sizeof(line),
                  "target_va=%px  kernel_pa(=IPA in Realm)=0x%llx\n"
                  "page-aligned IPA for cmd 4 = 0x%llx\n",
                  (void *)target_word,
                  (unsigned long long)pa,
                  (unsigned long long)(pa & PAGE_MASK));

    if (n > len)
        n = len;
    if (copy_to_user(buf, line, n))
        return -EFAULT;
    *off += n;
    return n;
}

static const struct proc_ops f3_proc_ops = {
    .proc_read  = f3_proc_read,
    .proc_write = f3_proc_write,
};

static int __init f3_init(void)
{
    struct page *pg;
    phys_addr_t pa = 0;

    // One page, private to this module. vmalloc gives page-granular memory.
    target_page = vmalloc(PAGE_SIZE);
    if (!target_page) {
        pr_err(F3_TAG ": vmalloc failed\n");
        return -ENOMEM;
    }
    memset(target_page, 0, PAGE_SIZE);

    // Store to the very start of the page so the trap IPA == page base.
    target_word = (unsigned long *)target_page;

    pg = vmalloc_to_page(target_page);
    if (pg)
        pa = page_to_phys(pg);

    proc_entry = proc_create(F3_TAG "_trigger", 0666, NULL, &f3_proc_ops);
    if (!proc_entry) {
        vfree(target_page);
        pr_err(F3_TAG ": proc_create failed\n");
        return -ENOMEM;
    }

    pr_err(F3_TAG ": loaded.\n");
    pr_err(F3_TAG ": target_va=%px\n", target_page);
    pr_err(F3_TAG ": kernel_pa(=IPA)=0x%llx page_base=0x%llx\n",
           (unsigned long long)pa,
           (unsigned long long)(pa & PAGE_MASK));
    pr_err(F3_TAG ": NEXT -> a1_test_arm 2 0x%px to confirm IPA via RMM, "
           "then a1_test_arm 4 <page-aligned IPA>, then echo 1 > "
           "/proc/" F3_TAG "_trigger\n", target_page);
    return 0;
}

static void __exit f3_exit(void)
{
    if (proc_entry)
        proc_remove(proc_entry);
    if (target_page)
        vfree(target_page);
    pr_err(F3_TAG ": unloaded\n");
}

module_init(f3_init);
module_exit(f3_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RealmEye F3 stage-2 trap validation stimulus (vmalloc target + /proc trigger)");
