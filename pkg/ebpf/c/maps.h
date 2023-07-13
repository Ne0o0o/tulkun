#ifndef __MAPS_H__
#define __MAPS_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <types.h>

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} execve_perf SEC(".maps");

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

// event buffer in map
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, event_data_t);
    __uint(max_entries, 10);
} event_data_map SEC(".maps");

#endif /* __MAPS_H__ */