/*
 * monitor.c - Multi-Container Memory Monitor (Linux Kernel Module)
 *
 * Completed implementation:
 *   - container_node linked-list struct with per-entry soft/hard limits
 *   - global container_list protected by monitor_lock (spinlock)
 *   - timer_callback: periodic RSS check, soft-limit warning, hard-limit kill
 *   - IOCTL REGISTER: validates pid/limits, guards against duplicates, inserts node
 *   - IOCTL UNREGISTER: removes node by PID, returns -ENOENT if not found
 *   - monitor_exit: drains list and releases spinlock before device teardown
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "monitor_ioctl.h"

#define DEVICE_NAME "container_monitor"
#define CHECK_INTERVAL_SEC 1

/* Container tracking node — one per registered PID.
 * Protected by monitor_lock across ioctl and timer code paths. */
struct container_node {
    pid_t pid;
    char container_id[32];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    bool soft_limit_warned;
    struct list_head list;
};

/* Global list of monitored containers and the spinlock that guards it.
 *
 * A spinlock is required (not a mutex) because timer_callback runs in
 * softirq context (TIMER_SOFTIRQ), which is atomic and may not sleep.
 * Mutexes may sleep while acquiring, so they must never be used in
 * atomic/softirq context.
 *
 * From process context (ioctl handlers) we use spin_lock_bh / spin_unlock_bh
 * to disable bottom-half processing and prevent a deadlock with the timer
 * softirq on the same CPU.  Inside the timer callback itself, BH is already
 * disabled, so plain spin_lock / spin_unlock are used there. */
static LIST_HEAD(container_list);
static DEFINE_SPINLOCK(monitor_lock);

/* --- Provided: internal device / timer state --- */
static struct timer_list monitor_timer;
static dev_t dev_num;
static struct cdev c_dev;
static struct class *cl;

/* ---------------------------------------------------------------
 * Provided: RSS Helper
 *
 * Returns the Resident Set Size in bytes for the given PID,
 * or -1 if the task no longer exists.
 * --------------------------------------------------------------- */
static long get_rss_bytes(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct *mm;
    long rss_pages = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -1;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (mm) {
        rss_pages = get_mm_rss(mm);
        mmput(mm);
    }
    put_task_struct(task);

    return rss_pages * PAGE_SIZE;
}

/* ---------------------------------------------------------------
 * Provided: soft-limit helper
 *
 * Log a warning when a process exceeds the soft limit.
 * --------------------------------------------------------------- */
static void log_soft_limit_event(const char *container_id,
                                 pid_t pid,
                                 unsigned long limit_bytes,
                                 long rss_bytes)
{
    printk(KERN_WARNING
           "[container_monitor] SOFT LIMIT container=%s pid=%d rss=%ld limit=%lu\n",
           container_id, pid, rss_bytes, limit_bytes);
}

/* ---------------------------------------------------------------
 * Provided: hard-limit helper
 *
 * Kill a process when it exceeds the hard limit.
 * --------------------------------------------------------------- */
static void kill_process(const char *container_id,
                         pid_t pid,
                         unsigned long limit_bytes,
                         long rss_bytes)
{
    struct task_struct *task;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        send_sig(SIGKILL, task, 1);
    rcu_read_unlock();

    printk(KERN_WARNING
           "[container_monitor] HARD LIMIT container=%s pid=%d rss=%ld limit=%lu\n",
           container_id, pid, rss_bytes, limit_bytes);
}

/* ---------------------------------------------------------------
 * Timer Callback - fires every CHECK_INTERVAL_SEC seconds.
 *
 * Iterates all tracked entries under the monitor_lock:
 *   - removes entries for processes that have already exited
 *   - enforces the hard limit (SIGKILL + remove entry)
 *   - emits a one-shot soft-limit warning per entry; resets the
 *     warned flag if RSS later drops back below the soft limit
 * Uses list_for_each_entry_safe so nodes can be deleted mid-walk.
 * --------------------------------------------------------------- */
static void timer_callback(struct timer_list *t)
{
    struct container_node *node, *tmp;
    long rss;

    /* In softirq context: BH is already disabled, plain spin_lock suffices. */
    spin_lock(&monitor_lock);
    list_for_each_entry_safe(node, tmp, &container_list, list) {
        rss = get_rss_bytes(node->pid);

        /* Remove entry if the process has already exited. */
        if (rss < 0) {
            list_del(&node->list);
            kfree(node);
            continue;
        }

        /* Hard limit: kill the process and remove the entry. */
        if ((unsigned long)rss > node->hard_limit_bytes) {
            kill_process(node->container_id, node->pid, node->hard_limit_bytes, rss);
            list_del(&node->list);
            kfree(node);
            continue;
        }

        /* Soft limit: emit a one-shot warning; reset flag when RSS drops. */
        if ((unsigned long)rss > node->soft_limit_bytes) {
            if (!node->soft_limit_warned) {
                log_soft_limit_event(node->container_id, node->pid,
                                     node->soft_limit_bytes, rss);
                node->soft_limit_warned = true;
            }
        } else {
            node->soft_limit_warned = false;
        }
    }
    spin_unlock(&monitor_lock);

    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
}

/* ---------------------------------------------------------------
 * IOCTL Handler
 *
 * Supported operations:
 *   - register a PID with soft + hard limits
 *   - unregister a PID when the runtime no longer needs tracking
 * --------------------------------------------------------------- */
static long monitor_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct monitor_request req;

    (void)f;

    if (cmd != MONITOR_REGISTER && cmd != MONITOR_UNREGISTER)
        return -EINVAL;

    if (copy_from_user(&req, (struct monitor_request __user *)arg, sizeof(req)))
        return -EFAULT;

    if (cmd == MONITOR_REGISTER) {
        struct container_node *new_node, *existing;

        /* Reject PID 0 (idle/swapper) and negative PIDs — neither is a
         * valid target for container monitoring from userspace. */
        if (req.pid <= 0)
            return -EINVAL;
        if (req.soft_limit_bytes > req.hard_limit_bytes)
            return -EINVAL;

        printk(KERN_INFO
               "[container_monitor] Registering container=%s pid=%d soft=%lu hard=%lu\n",
               req.container_id, req.pid, req.soft_limit_bytes, req.hard_limit_bytes);

        new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
        if (!new_node)
            return -ENOMEM;

        new_node->pid              = req.pid;
        new_node->soft_limit_bytes = req.soft_limit_bytes;
        new_node->hard_limit_bytes = req.hard_limit_bytes;
        new_node->soft_limit_warned = false;
        /* Ensure null-termination regardless of source string length;
         * kmalloc does not zero memory. */
        strncpy(new_node->container_id, req.container_id,
                sizeof(new_node->container_id) - 1);
        new_node->container_id[sizeof(new_node->container_id) - 1] = '\0';
        INIT_LIST_HEAD(&new_node->list);

        spin_lock_bh(&monitor_lock);
        /* Linear scan for duplicate detection is acceptable for the small
         * number of containers expected in this runtime (O(n) per insert).
         * For large-scale use a hash table (kernel hlist) would give O(1). */
        list_for_each_entry(existing, &container_list, list) {
            if (existing->pid == req.pid) {
                spin_unlock_bh(&monitor_lock);
                kfree(new_node);
                return -EEXIST;
            }
        }
        list_add(&new_node->list, &container_list);
        spin_unlock_bh(&monitor_lock);
        return 0;
    }

    printk(KERN_INFO
           "[container_monitor] Unregister request container=%s pid=%d\n",
           req.container_id, req.pid);

    /* Search by PID; remove and free the matching entry if found. */
    {
        struct container_node *node, *tmp;
        int found = 0;

        spin_lock_bh(&monitor_lock);
        list_for_each_entry_safe(node, tmp, &container_list, list) {
            if (node->pid == req.pid) {
                list_del(&node->list);
                kfree(node);
                found = 1;
                break;
            }
        }
        spin_unlock_bh(&monitor_lock);
        return found ? 0 : -ENOENT;
    }
}

/* --- Provided: file operations --- */
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = monitor_ioctl,
};

/* --- Provided: Module Init --- */
static int __init monitor_init(void)
{
    if (alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME) < 0)
        return -1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    cl = class_create(DEVICE_NAME);
#else
    cl = class_create(THIS_MODULE, DEVICE_NAME);
#endif
    if (IS_ERR(cl)) {
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(cl);
    }

    if (IS_ERR(device_create(cl, NULL, dev_num, NULL, DEVICE_NAME))) {
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    cdev_init(&c_dev, &fops);
    if (cdev_add(&c_dev, dev_num, 1) < 0) {
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    timer_setup(&monitor_timer, timer_callback, 0);
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);

    printk(KERN_INFO "[container_monitor] Module loaded. Device: /dev/%s\n", DEVICE_NAME);
    return 0;
}

/* --- Provided: Module Exit --- */
static void __exit monitor_exit(void)
{
    struct container_node *node, *tmp;

    timer_shutdown_sync(&monitor_timer);

    spin_lock_bh(&monitor_lock);
    list_for_each_entry_safe(node, tmp, &container_list, list) {
        list_del(&node->list);
        kfree(node);
    }
    spin_unlock_bh(&monitor_lock);

    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);

    printk(KERN_INFO "[container_monitor] Module unloaded.\n");
}

module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Supervised multi-container memory monitor");
