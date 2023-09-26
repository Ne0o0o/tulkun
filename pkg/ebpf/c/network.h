#ifndef __COMMON_NETWORK_H__
#define __COMMON_NETWORK_H__

#include <vmlinux.h>
#include <vmlinux_flavors.h>

#include <bpf/bpf_endian.h>

static __always_inline u16 get_sockaddr_family(struct sockaddr *address)
{
    return BPF_CORE_READ(address, sa_family);
}