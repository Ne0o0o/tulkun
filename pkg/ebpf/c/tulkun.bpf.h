// +build ignore
#include <vmlinux.h>
#include <vmlinux_missing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define DNS_DATA_LEN 128
#define COMM_DATA_LEN 64
#define FILENAME_DATA_LEN 64

#define ETH_HLEN sizeof(struct ethhdr)
#define IPH_HLEN sizeof(struct iphdr)
#define UDPH_HLEN sizeof(struct udphdr)
#define TCPH_HLEN sizeof(struct tcphdr)
#define DNSH_HLEN sizeof(struct dnshdr)

#define ARGS_BUF_SIZE 38 * 64 + 2
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
    u32 buf_off;
    char buf[ARGS_BUF_SIZE];
} buffer_data_t;

typedef struct execve_event_new
{
    process_data_t process_info;
    char filename[FILENAME_DATA_LEN];
    buffer_data_t *argv;
} execve_event_t;
