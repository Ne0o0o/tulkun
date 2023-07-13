#ifndef __TYPES_H__
#define __TYPES_H__

#include <vmlinux.h>
#include <vmlinux_missing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define ARGS_BUF_SIZE 32000 // copy from tracee

#define DNS_DATA_LEN 128
#define COMM_DATA_LEN 64
#define FILENAME_DATA_LEN 64

#define ETH_HLEN sizeof(struct ethhdr)
#define IPH_HLEN sizeof(struct iphdr)
#define UDPH_HLEN sizeof(struct udphdr)
#define TCPH_HLEN sizeof(struct tcphdr)
#define DNSH_HLEN sizeof(struct dnshdr)

#define MAX_BUF_SIZE 1024 * 4
#define MAX_STR_ARR_ELEM 38 // TODO: turn this into global variables set w/ libbpfgo
#define MAX_STRING_SIZE 64  // same as PATH_MAX
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

struct port_key
{
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct port_val
{
    u32 pid;
    u32 uid;
    u32 gid;
    u32 tgid;
    char comm[COMM_DATA_LEN];
};

struct dns_event_user
{
    u32 ifindex;
    u32 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char dns[DNS_DATA_LEN];
};

struct execve_event
{
    u32 pid;
    u32 uid;
    u32 gid;
    u32 tgid;
    char filename[FILENAME_DATA_LEN];
    char argv[128];
    char envp[128];
};

struct dns_event_kernel
{
    u32 ifindex;
    u32 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char dns[DNS_DATA_LEN];
    u32 pid;
    u32 uid;
    u32 gid;
    u32 tgid;
    char comm[COMM_DATA_LEN];
};

struct dnshdr
{
    u16 id;
    u16 flags;
    u16 qcount;
    u16 answerrr;
    u16 authrr;
    u16 addrr;
};

typedef struct process_data
{
    u32 pid;
    u32 uid;
    u32 gid;
    u32 tgid;
    char tty[64];
} process_data_t;

typedef struct buffer_data
{
    char buf[MAX_BUF_SIZE];
    u32 buf_off;
} buffer_data_t;

typedef struct task_context
{
    u64 start_time; // thread's start time
    u64 cgroup_id;
    u32 pid;       // PID as in the userspace term
    u32 tid;       // TID as in the userspace term
    u32 ppid;      // Parent PID as in the userspace term
    u32 host_pid;  // PID in host pid namespace
    u32 host_tid;  // TID in host pid namespace
    u32 host_ppid; // Parent PID in host pid namespace
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    u32 flags;

} task_context_t;

typedef struct event_context
{
    u64 ts; // Timestamp
    task_context_t task;
    // u32 eventid;
    s32 syscall;      // The syscall which triggered the event
                      // u64 matched_policies;
                      // s64 retval;
                      // u32 stack_id;
    u16 processor_id; // The ID of the processor which processed the event
    u8 argnum;
} event_context_t;

typedef struct event_data
{
    event_context_t context;
    buffer_data_t buf;
    //  struct task_struct *task;
    u64 param_types;
} event_data_t;

typedef struct program_data
{
    // config_entry_t *config;
    // task_info_t *task_info;
    struct task_struct *task;
    event_data_t *event; // event data to submit
    // scratch_t *scratch;
    void *ctx;
} program_data_t;

#endif /* __TYPES_H__ */