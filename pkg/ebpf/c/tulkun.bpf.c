// +build ignore
#include <tulkun.bpf.h>
#include <common.h>
#include <maps.h>
#include <types.h>

#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define DROP_PACKET 0
#define PASS_PACKET -1

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
        bpf_get_current_comm(val.comm, COMM_DATA_LEN);
        // Write the value into the eBPF table:
        bpf_map_update_elem(&ports_process, &key, &val, BPF_ANY);
    }
    return 0;
}

SEC("socket")
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
    // if (skb->ingress_ifindex != 0)
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
    for (i = 0; i < DNS_DATA_LEN; i++)
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
        __builtin_memcpy(e->comm, p_val->comm, sizeof(p_val->comm));
    }

    bpf_ringbuf_submit(e, 0);
    return DROP_PACKET;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    // int execve(const char *filename, char *const argv[], char *const envp[])
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
    {
        return 0;
    }
    if (!save_str_arr_to_buf(&p.event->buf, (void *)(ctx->args[1]) /*argv*/))
    {
        return 0;
    }
    p.event->buf.arg_num += 1;
    if (!save_str_arr_to_buf(&p.event->buf, (void *)(ctx->args[2]) /*envp*/))
    {
        return 0;
    }
    p.event->buf.arg_num += 1;
    u32 size = sizeof(event_context_t) + sizeof(p.event->buf.arg_num) + sizeof(p.event->buf.buf_off) + p.event->buf.buf_off;
    if (size > sizeof(event_context_t) + MAX_BUF_SIZE - 1)
    {
        return 0;
    }
    // void *output_data = p.event;
    bpf_perf_event_output(ctx, &execve_perf, BPF_F_CURRENT_CPU, p.event, size);
    return 0;
}
