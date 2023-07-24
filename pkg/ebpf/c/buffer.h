#ifndef __COMMON_BUFFER_H__
#define __COMMON_BUFFER_H__

#include <maps.h>

#include <vmlinux.h>

static __always_inline buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

#endif