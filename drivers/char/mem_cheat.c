#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/list.h>
#include <linux/kobject.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Official Custom Integration");
MODULE_DESCRIPTION("Xiaomi 11T Pro Secure Kernel Memory Tool");

#define DEVICE_NAME "mem_cheat"

#define IOCTL_MEM_READ  _IOWR('k', 1, struct ioctl_mem_arg)
#define IOCTL_MEM_WRITE _IOWR('k', 2, struct ioctl_mem_arg)

struct ioctl_mem_arg {
    pid_t pid;
    unsigned long address;
    void __user *buffer;
    size_t size;
};

static int major_num;

static long native_kernel_mem_rw(pid_t target_pid, unsigned long address, void *buf, size_t size, int is_write) {
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    long copied = 0;

    pid_struct = find_get_pid(target_pid);
    if (!pid_struct) return -EINVAL;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return -EINVAL;
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        put_pid(pid_struct);
        return -EINVAL;
    }

    if (is_write) {
        copied = access_process_vm(task, address, buf, size, FOLL_WRITE);
    } else {
        copied = access_process_vm(task, address, buf, size, 0);
    }

    mmput(mm);
    put_task_struct(task);
    put_pid(pid_struct);

    return copied;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct ioctl_mem_arg kernel_arg;
    void *kernel_buffer;
    long result;

    if (copy_from_user(&kernel_arg, (void __user *)arg, sizeof(struct ioctl_mem_arg))) {
        return -EFAULT;
    }

    if (kernel_arg.size <= 0 || kernel_arg.size > 8192) {
        return -EINVAL; 
    }

    kernel_buffer = kmalloc(kernel_arg.size, GFP_KERNEL);
    if (!kernel_buffer) return -ENOMEM;

    switch (cmd) {
        case IOCTL_MEM_READ:
            result = native_kernel_mem_rw(kernel_arg.pid, kernel_arg.address, kernel_buffer, kernel_arg.size, 0);
            if (result > 0) {
                if (copy_to_user(kernel_arg.buffer, kernel_buffer, kernel_arg.size)) {
                    result = -EFAULT;
                }
            }
            break;

        case IOCTL_MEM_WRITE:
            if (copy_from_user(kernel_buffer, kernel_arg.buffer, kernel_arg.size)) {
                kfree(kernel_buffer);
                return -EFAULT;
            }
            result = native_kernel_mem_rw(kernel_arg.pid, kernel_arg.address, kernel_buffer, kernel_arg.size, 1);
            break;

        default:
            kfree(kernel_buffer);
            return -EINVAL;
    }

    kfree(kernel_buffer);
    return result;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = device_ioctl,
};

static int __init mem_cheat_init(void) {
    major_num = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_num < 0) {
        return major_num;
    }
    return 0;
}

static void __exit mem_cheat_exit(void) {
    if (major_num >= 0) {
        unregister_chrdev(major_num, DEVICE_NAME);
    }
}

module_init(mem_cheat_init);
module_exit(mem_cheat_exit);
