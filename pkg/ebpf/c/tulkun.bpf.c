// +build ignore
#include <tulkun.bpf.h>

#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define DROP_PACKET 0
#define PASS_PACKET -1

/* BPF ringbuf map for dns socket filter output event */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 16);
} socket_events SEC(".maps");

/* BFP lru hash map for dns socket filter secarh process */
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct port_key);
    __type(value, struct port_val);
    __uint(max_entries, 512);
} ports_process SEC(".maps");

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk)
{
    // struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport = BPF_CORE_READ(sk, sk_num);
    u16 dport = BPF_CORE_READ(sk, sk_dport);
    // Processing only packets on port 53.
    // 13568 = ntohs(53);

    if (sport == bpf_ntohs(53) || dport == bpf_ntohs(53))
    {
        // Preparing the data:
        u32 saddr = BPF_CORE_READ(sk, sk_rcv_saddr);
        u32 daddr = BPF_CORE_READ(sk, sk_daddr);
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();
        // Forming the structure-key.
        struct port_key key = {.proto = IPPROTO_UDP};
        key.saddr = bpf_ntohl(saddr);
        key.daddr = bpf_ntohl(daddr);
        key.sport = sport;
        key.dport = bpf_ntohs(dport);
        // Forming a structure with socket pbt:
        struct port_val val = {};
        val.pid = pid_tgid >> 32;
        val.tgid = (u32)pid_tgid;
        val.uid = (u32)uid_gid;
        val.gid = uid_gid >> 32;
        bpf_get_current_comm(val.comm, COMM_DATA_BUF);
        // Write the value into the eBPF table:
        bpf_map_update_elem(&ports_process, &key, &val, BPF_ANY);
    }
    return 0;
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(kretprobe_udp_sendmsg)
{
    struct port_key key = {};
    struct port_val *p_val = bpf_map_lookup_elem(&ports_process, &key);
    if (!p_val)
    {
        return 0;
    }
    char success[] = "kretprobe udp_sendmsg get key success\n";
    bpf_trace_printk(success, sizeof(success));
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport = BPF_CORE_READ(sk, sk_num);
    u16 dport = BPF_CORE_READ(sk, sk_dport);
    // Processing only packets on port 53.
    // 13568 = ntohs(53);

    if (sport == bpf_ntohs(53) || dport == bpf_ntohs(53))
    {
        // preparing the data:
        u32 saddr = BPF_CORE_READ(sk, sk_rcv_saddr);
        u32 daddr = BPF_CORE_READ(sk, sk_daddr);
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();
        // Forming the structure-key.
        struct port_key key = {.proto = IPPROTO_TCP};
        key.saddr = bpf_ntohl(saddr);
        key.daddr = bpf_ntohl(daddr);
        key.sport = sport;
        key.dport = bpf_ntohs(dport);
        // Form a structure with socket properties:
        struct port_val val = {};
        val.pid = pid_tgid >> 32;
        val.tgid = (u32)pid_tgid;
        val.uid = (u32)uid_gid;
        val.gid = uid_gid >> 32;
        bpf_get_current_comm(val.comm, COMM_DATA_BUF);
        // Write the value into the eBPF table:
        bpf_map_update_elem(&ports_process, &key, &val, BPF_ANY);
    }
    return 0;
}

SEC("socket/sock_filter")
int dns_filter_user(struct __sk_buff *skb)
{
    u16 offset = 0;
    struct ethhdr eth_hdr;
    if (bpf_skb_load_bytes(skb, offset, &eth_hdr, ETH_HLEN) < 0)
        return DROP_PACKET;
    if (bpf_ntohs(eth_hdr.h_proto) != ETH_P_IP)
        return DROP_PACKET;

    offset += ETH_HLEN;
    struct iphdr ip_hdr;
    if (bpf_skb_load_bytes(skb, offset, &ip_hdr, IPH_HLEN) < 0)
        return DROP_PACKET;

    if (ip_hdr.protocol != IPPROTO_UDP)
        return DROP_PACKET;

    offset += IPH_HLEN;
    struct udphdr udp_hdr;
    if (bpf_skb_load_bytes(skb, offset, &udp_hdr, UDPH_HLEN) < 0)
        return DROP_PACKET;

    // drop packet if is not dns request
    if (udp_hdr.dest != bpf_ntohs(53))
        return DROP_PACKET;

    offset += UDPH_HLEN;
    struct dnshdr dns_hdr;
    if (bpf_skb_load_bytes(skb, offset, &dns_hdr, DNSH_HLEN) < 0)
        return DROP_PACKET;
    // dorp packet if not request
    if ((dns_hdr.flags >> 15) != 0)
        return DROP_PACKET;

    // drop packet if is not ingress (dns requests)
    if (skb->ingress_ifindex != 0)
        return DROP_PACKET;

    offset += DNSH_HLEN;
    struct dns_event_user *e;
    e = bpf_ringbuf_reserve(&socket_events, sizeof(*e), 0);
    if (!e)
    {
        return DROP_PACKET;
    }
    e->saddr = bpf_ntohl(ip_hdr.saddr);
    e->daddr = bpf_ntohl(ip_hdr.daddr);
    e->sport = bpf_ntohs(udp_hdr.source);
    e->dport = bpf_ntohs(udp_hdr.dest);
    e->ifindex = skb->ifindex;
    e->proto = IPPROTO_UDP;
    // copy buffer

    u32 i;
    for (i = 0; i < DNS_DATA_BUF; i++)
    {
        bpf_skb_load_bytes(skb, offset + i, &e->dns[i], 1);
        if (e->dns[i] == '\0')
            break;
    }

    bpf_ringbuf_submit(e, 0);
    return DROP_PACKET;
}

SEC("socket/sock_filter")
int dns_filter_kernel(struct __sk_buff *skb)
{
    u16 offset = 0;
    struct ethhdr eth_hdr;
    if (bpf_skb_load_bytes(skb, offset, &eth_hdr, ETH_HLEN) < 0)
        return DROP_PACKET;
    if (bpf_ntohs(eth_hdr.h_proto) != ETH_P_IP)
        return DROP_PACKET;

    offset += ETH_HLEN;
    struct iphdr ip_hdr;
    if (bpf_skb_load_bytes(skb, offset, &ip_hdr, IPH_HLEN) < 0)
        return DROP_PACKET;

    if (ip_hdr.protocol != IPPROTO_UDP)
        return DROP_PACKET;

    offset += IPH_HLEN;
    struct udphdr udp_hdr;
    if (bpf_skb_load_bytes(skb, offset, &udp_hdr, UDPH_HLEN) < 0)
        return DROP_PACKET;

    // drop packet if is not dns request
    if (udp_hdr.dest != bpf_ntohs(53))
        return DROP_PACKET;

    offset += UDPH_HLEN;
    struct dnshdr dns_hdr;
    if (bpf_skb_load_bytes(skb, offset, &dns_hdr, DNSH_HLEN) < 0)
        return DROP_PACKET;
    // dorp packet if not request
    if ((dns_hdr.flags >> 15) != 0)
        return DROP_PACKET;

    // drop packet if is not ingress (dns requests)
    //if (skb->ingress_ifindex != 0)
    //    return DROP_PACKET;

    offset += DNSH_HLEN;
    struct dns_event_kernel *e;
    e = bpf_ringbuf_reserve(&socket_events, sizeof(*e), 0);
    if (!e)
    {
        return DROP_PACKET;
    }
    e->saddr = bpf_ntohl(ip_hdr.saddr);
    e->daddr = bpf_ntohl(ip_hdr.daddr);
    e->sport = bpf_ntohs(udp_hdr.source);
    e->dport = bpf_ntohs(udp_hdr.dest);
    e->ifindex = skb->ifindex;
    e->proto = IPPROTO_UDP;

    u32 i;
    for (i = 0; i < DNS_DATA_BUF; i++)
    {
        bpf_skb_load_bytes(skb, offset + i, &e->dns[i], 1);
        if (e->dns[i] == '\0')
            break;
    }

    struct port_key key = {.proto = IPPROTO_UDP};
    key.saddr = bpf_ntohl(ip_hdr.saddr);
    key.daddr = bpf_ntohl(ip_hdr.daddr);
    key.sport = bpf_ntohs(udp_hdr.source);
    key.dport = bpf_ntohs(udp_hdr.dest);

    struct port_val *p_val = bpf_map_lookup_elem(&ports_process, &key);
    if (p_val)
    {
        e->pid = p_val->pid;
        e->uid = p_val->uid;
        e->gid = p_val->gid;
        memcpy(e->comm, p_val->comm, sizeof(p_val->comm));
    }

    bpf_ringbuf_submit(e, 0);
    return DROP_PACKET;
}

char _license[] SEC("license") = "GPL";