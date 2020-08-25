#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/tty.h>

#define ARGSIZE  128
#define TTYSIZE 64

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    int ancestor;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    char tty[TTYSIZE];
    u32 uid;
    u32 gid;
    int ret_val;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int hld_syscall_execve_entry(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAX_ARGS; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int hld_syscall_execve_return(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;
    int ancestor = false;
    struct task_struct *parent_task;
    char compare_buf[sizeof("ANCESTOR_NAME")];

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    // Try to find ancestor of this process
    parent_task = task->real_parent;
    #pragma unroll
    for (int i = 0; i < MAX_ANCESTORS - 1; i++) {
        bpf_probe_read(&compare_buf, sizeof(compare_buf), parent_task->comm);
        // No access to libc::strcmp allowed and __builtin_memcmp doesn't seem to work on 18.04.
        #pragma unroll
        for (int j = 0; j < sizeof(compare_buf) - 1; j++) {
            char left = "ANCESTOR_NAME"[j];
            char right = compare_buf[j];
            if (left == right) {
                ancestor = true;
            } else {
                ancestor = false;
                goto cmp_done;
            }
        }
cmp_done:
        if (ancestor) {
            goto find_done;
        }
        parent_task = parent_task->real_parent;
    }
find_done:
    data.ancestor = ancestor;

    bpf_probe_read_str(data.tty, TTYSIZE, task->signal->tty->name);

    data.uid = task->cred->uid.val;
    data.gid = task->cred->gid.val;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.ret_val = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
