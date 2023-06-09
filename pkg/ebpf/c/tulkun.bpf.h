// +build ignore
#include <common.h>
#include <vmlinux.h>
#include <types.h>
#include <maps.h>
#include <vmlinux_missing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

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

static __always_inline int init_program_data(program_data_t *p, void *ctx)
{
    long ret = 0;
    int zero = 0;

    // allow caller to specify a stack/map based event_data_t pointer

    if (p->event == NULL)
    {
        p->event = bpf_map_lookup_elem(&event_data_map, &zero);
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

    __builtin_memset(p->event->context.task.comm, 0, sizeof(p->event->context.task.comm));
    ret = bpf_get_current_comm(&p->event->context.task.comm, sizeof(p->event->context.task.comm));
    if (unlikely(ret < 0))
    {
        // disable logging as a workaround for instruction limit verifier error on kernel 4.19
        // tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_GET_CURRENT_COMM, ret);
        return 0;
    }
    char *uts_name = get_task_uts_name(p->task);
    if (uts_name)
    {
        __builtin_memset(p->event->context.task.uts_name, 0, sizeof(p->event->context.task.uts_name));
        bpf_probe_read_str(&p->event->context.task.uts_name, TASK_COMM_LEN, uts_name);
    }
    p->event->context.ts = bpf_ktime_get_ns();
    p->event->context.argnum = 0;
    // current context

    p->event->context.processor_id = (u16)bpf_get_smp_processor_id();
    p->ctx = ctx;

    // reset buf offset
    p->event->buf.buf_off = 0;
    return 1;
}

static __always_inline int save_str_arr_to_buf(buffer_data_t *buffer, const char __user *const __user *ptr)
{
    // Data saved to submit buf: [string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;
    if (buffer->buf_off > MAX_BUF_SIZE - 1)
        return 0;

    // Save argument index
    // event->args[event->buf_off] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = buffer->buf_off;
    buffer->buf_off += 1;
    if (ptr == NULL)
        goto out;
#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++)
    {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (buffer->buf_off > MAX_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz =
            bpf_probe_read_str(&(buffer->buf[buffer->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0)
        {
            if (buffer->buf_off > MAX_BUF_SIZE - sizeof(int))
                // Satisfy validator
                goto out;
            bpf_probe_read(&(buffer->buf[buffer->buf_off]), sizeof(int), &sz);
            buffer->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        }
        else
        {
            goto out;
        }
    }
out:
    // save number of elements in the array
    if (orig_off > MAX_BUF_SIZE - 1)
        return 0;
    buffer->buf[orig_off] = elem_num;
    return 1;
}
