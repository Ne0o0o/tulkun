// +build ignore
#include <arch.h>
#include <filesystem.h>
#include <maps.h>
#include <common.h>
#include <types.h>

#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define NO_SYSCALL -1

static __always_inline int get_task_flags(struct task_struct *task)
{
    return READ_KERN(task->flags);
}

static __always_inline u64 get_task_start_time(struct task_struct *task)
{
    return READ_KERN(task->start_time);
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->tgid);
}

static __always_inline char *get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
    return READ_KERN(uts_ns->name.nodename);
}

static __always_inline char *get_task_tty(struct task_struct *task)
{
    struct signal_struct *signal = READ_KERN(task->signal);
    struct tty_struct *tty = READ_KERN(signal->tty);
    return READ_KERN(tty->name);
}

static __always_inline int get_task_syscall_id(struct task_struct *task)
{
    // There is no originated syscall in kernel thread context
    if (get_task_flags(task) & PF_KTHREAD)
    {
        return NO_SYSCALL;
    }
    struct pt_regs *regs = get_task_pt_regs(task);
    return get_syscall_id_from_regs(regs);
}

static __always_inline int fill_net_conn_context(struct sock *sk, net_conn_v4_t *conn, int peer)
{
    if (peer)
    {
        conn->remote_port = BPF_CORE_READ(sk, sk_num);
        conn->local_port = bpf_ntohs(BPF_CORE_READ(sk, sk_dport));
        conn->remote_address = bpf_ntohl(BPF_CORE_READ(sk, sk_rcv_saddr));
        conn->local_address = bpf_ntohl(BPF_CORE_READ(sk, sk_daddr));
    }
    else
    {
        conn->local_port = BPF_CORE_READ(sk, sk_num);
        conn->remote_port = bpf_ntohs(BPF_CORE_READ(sk, sk_dport));
        conn->local_address = bpf_ntohl(BPF_CORE_READ(sk, sk_rcv_saddr));
        conn->remote_address = bpf_ntohl(BPF_CORE_READ(sk, sk_daddr));
    }
    return 0;
}

static __always_inline int fill_task_context(struct task_struct *task, task_context_t *t)
{
    long ret = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    t->start_time = get_task_start_time(task);
    t->host_tid = pid_tgid;
    t->host_pid = pid_tgid >> 32;
    t->host_ppid = get_task_ppid(task);
    t->uid = bpf_get_current_uid_gid();
    t->cgroup_id = bpf_get_current_cgroup_id();
    // task command
    __builtin_memset(t->comm, 0, sizeof(t->comm));
    ret = bpf_get_current_comm(&t->comm, sizeof(t->comm));
    if (unlikely(ret < 0))
    {
        // disable logging as a workaround for instruction limit verifier error on kernel 4.19
        // tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_GET_CURRENT_COMM, ret);
        return 0;
    }
    // uts name
    char *uts_name = get_task_uts_name(task);
    if (uts_name)
    {
        __builtin_memset(t->uts_name, 0, sizeof(t->uts_name));
        bpf_probe_read_str(&t->uts_name, TASK_LEN_16, uts_name);
    }
    // tty name
    char *tty_name = get_task_tty(task);
    if (tty_name)
    {
        __builtin_memset(t->tty, 0, sizeof(t->tty));
        bpf_probe_read_str(&t->tty, TASK_LEN_16, tty_name);
    }
    // stdin and stdout
    struct file *stdin_f = get_task_fd(task, 0);
    if (stdin_f)
    {
        struct path path = READ_KERN(stdin_f->f_path);
        void *stdin = get_path_str(__builtin_preserve_access_index(&path));
        __builtin_memset(t->stdin, 0, sizeof(t->stdin));
        bpf_probe_read_str(&t->stdin, TASK_LEN_16, stdin);
    }

    struct file *stdout_f = get_task_fd(task, 1);
    if (stdout_f)
    {
        struct path path = READ_KERN(stdout_f->f_path);
        void *stdout = get_path_str(__builtin_preserve_access_index(&path));
        __builtin_memset(t->stdout, 0, sizeof(t->stdout));
        bpf_probe_read_str(&t->stdout, TASK_LEN_16, stdout);
    }

    // reset flags
    t->flags = 0;
    return 1;
}

static __always_inline int init_syscall_data(syscall_program_t *p, void *ctx)
{
    long ret = 0;
    int zero = 0;

    // allow caller to specify a stack/map based syscall_event_data_t pointer

    if (p->event == NULL)
    {
        p->event = bpf_map_lookup_elem(&syscall_buf, &zero);
        if (unlikely(p->event == NULL))
            return 0;
    }

    // current task info
    p->task = (struct task_struct *)bpf_get_current_task();
    // current context info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    p->event->context.task.start_time = get_task_start_time(p->task);
    p->event->context.task.host_tid = pid_tgid;
    p->event->context.task.host_pid = pid_tgid >> 32;
    p->event->context.task.host_ppid = get_task_ppid(p->task);
    p->event->context.task.uid = bpf_get_current_uid_gid();
    p->event->context.task.cgroup_id = bpf_get_current_cgroup_id();

    __builtin_memset(p->event->context.task.comm, 0, sizeof(p->event->context.task.comm));
    ret = bpf_get_current_comm(&p->event->context.task.comm, sizeof(p->event->context.task.comm));
    if (unlikely(ret < 0))
    {
        // disable logging as a workaround for instruction limit verifier error on kernel 4.19
        // tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_GET_CURRENT_COMM, ret);
        return 0;
    }
    // uts name
    char *uts_name = get_task_uts_name(p->task);
    if (uts_name)
    {
        __builtin_memset(p->event->context.task.uts_name, 0, sizeof(p->event->context.task.uts_name));
        bpf_probe_read_str(&p->event->context.task.uts_name, TASK_LEN_16, uts_name);
    }
    // tty name
    char *tty_name = get_task_tty(p->task);
    if (tty_name)
    {
        __builtin_memset(p->event->context.task.tty, 0, sizeof(p->event->context.task.tty));
        bpf_probe_read_str(&p->event->context.task.tty, TASK_LEN_16, tty_name);
    }
    // syscall num
    p->event->context.syscall = get_task_syscall_id(p->task);
    p->event->context.ts = bpf_ktime_get_ns();
    p->event->context.argnum = 0;
    // stdin and stdout
    struct file *stdin_f = get_task_fd(p->task, 0);
    if (stdin_f)
    {
        struct path path = READ_KERN(stdin_f->f_path);
        void *stdin = get_path_str(__builtin_preserve_access_index(&path));
        __builtin_memset(p->event->context.task.stdin, 0, sizeof(p->event->context.task.stdin));
        bpf_probe_read_str(&p->event->context.task.stdin, TASK_LEN_16, stdin);
    }

    struct file *stdout_f = get_task_fd(p->task, 1);
    if (stdout_f)
    {
        struct path path = READ_KERN(stdout_f->f_path);
        void *stdout = get_path_str(__builtin_preserve_access_index(&path));
        __builtin_memset(p->event->context.task.stdout, 0, sizeof(p->event->context.task.stdout));
        bpf_probe_read_str(&p->event->context.task.stdout, TASK_LEN_16, stdout);
    }
    // current context

    p->event->context.processor_id = (u16)bpf_get_smp_processor_id();
    p->ctx = ctx;

    // reset buf offset and args
    p->event->buf.buf_off = 0;
    p->event->buf.arg_num = 0;

    // reset flags
    p->event->context.task.flags = 0;

    return 1;
}

static __always_inline int init_net_conn_data(net_conn_program_t *p)
{
    int zero = 0;

    // init event buffer
    if (p->event == NULL)
    {
        p->event = bpf_map_lookup_elem(&net_conn_buf, &zero);
        if (p->event == NULL)
            return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // init task context
    fill_task_context(task, &p->event->context.task);
    // set timestamp
    p->event->context.ts = bpf_ktime_get_ns();
    // set processor id
    p->event->context.processor_id = (u16)bpf_get_smp_processor_id();
    // reset buf offset and args
    p->event->buf.buf_off = 0;
    p->event->buf.arg_num = 0;

    return 1;
}
