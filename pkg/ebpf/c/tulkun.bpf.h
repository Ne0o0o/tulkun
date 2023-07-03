// +build ignore
#include <vmlinux.h>

#define DNS_DATA_BUF 128
#define COMM_DATA_BUF 64
#define FILENAME_DATA_LEN 128

#define ETH_HLEN sizeof(struct ethhdr)
#define IPH_HLEN sizeof(struct iphdr)
#define UDPH_HLEN sizeof(struct udphdr)
#define TCPH_HLEN sizeof(struct tcphdr)
#define DNSH_HLEN sizeof(struct dnshdr)

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
    char comm[COMM_DATA_BUF];
};

struct dns_event_user
{
    u32 ifindex;
    u32 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char dns[DNS_DATA_BUF];
};

struct execve_event
{
    u32 pid;
    char filename[FILENAME_DATA_LEN];
};

struct dns_event_kernel
{
    u32 ifindex;
    u32 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char dns[DNS_DATA_BUF];
    u32 pid;
    u32 uid;
    u32 gid;
    u32 tgid;
    char comm[COMM_DATA_BUF];
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