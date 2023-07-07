// +build ignore
#include <tulkun.bpf.h>

#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define DROP_PACKET 0
#define PASS_PACKET -1

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 512 /* 256 KB */);
} execve_events SEC(".maps");

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

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, buffer_data_t);
    __uint(max_entries, 1024 * 512);
} buffer_data_maps SEC(".maps");

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

__always_inline int base_program_data(process_data_t *data)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();
    data->pid = pid_tgid >> 32;
    data->tgid = (u32)pid_tgid;
    data->uid = (u32)uid_gid;
    data->gid = uid_gid >> 32;
    return 1;
}

static buffer_data_t buf_zero = {};

__always_inline buffer_data_t *get_buffer_cache(u64 id)
{
    int ret = bpf_map_update_elem(&buffer_data_maps, &id,
                                  &buf_zero, BPF_NOEXIST);
    if (ret < 0)
    {
        return 0;
    }
    return bpf_map_lookup_elem(&buffer_data_maps, &id);
}

__always_inline int delete_buffer_cache(u64 id)
{
    return bpf_map_delete_elem(&buffer_data_maps, &id);
}

__always_inline int save_str_arr_to_buf(buffer_data_t *buffer, const char __user *const __user *ptr)
{
    // Data saved to submit buf: [string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;
    if (buffer->buf_off > ARGS_BUF_SIZE - 1)
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

        if (buffer->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz =
            bpf_probe_read_str(&(buffer->buf[buffer->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0)
        {
            if (buffer->buf_off > ARGS_BUF_SIZE - sizeof(int))
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
    if (orig_off > ARGS_BUF_SIZE - 1)
        return 0;
    buffer->buf[orig_off] = elem_num;
    return 1;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    // int execve(const char *filename, char *const argv[], char *const envp[])
    u64 id = bpf_get_current_pid_tgid();
    buffer_data_t *buf = get_buffer_cache(id);
    if (!buf)
    {
        return 0;
    }
    execve_event_t *e;
    e = bpf_ringbuf_reserve(&execve_events, sizeof(*e), 0);
    if (!e)
    {
        return 0;
    }
    if (!base_program_data(&e->process_info))
    {
        return 0;
    }

    bpf_core_read_user_str(&e->filename, sizeof(e->filename), (char *)(ctx->args[0]));
    save_str_arr_to_buf(buf, (void *)(ctx->args[1]) /*argv*/);

    bpf_probe_read(&e->argv, sizeof(buf), &buf);
    bpf_ringbuf_submit(e, 0);
    delete_buffer_cache(id);
    return 1;
}