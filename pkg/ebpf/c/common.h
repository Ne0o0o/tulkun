#ifndef __COMMON_H__
#define __COMMON_H__

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>

#define READ_KERN(ptr)                                    \
    ({                                                    \
        typeof(ptr) _val;                                 \
        __builtin_memset((void *)&_val, 0, sizeof(_val)); \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                             \
    })

#define READ_KERN_STR_INTO(dst, src) bpf_core_read_str((void *)&dst, sizeof(dst), src)

#define READ_USER(ptr)                                         \
    ({                                                         \
        typeof(ptr) _val;                                      \
        __builtin_memset((void *)&_val, 0, sizeof(_val));      \
        bpf_core_read_user((void *)&_val, sizeof(_val), &ptr); \
        _val;                                                  \
    })

#define BPF_READ(src, a, ...)                              \
    ({                                                     \
        ___type((src), a, ##__VA_ARGS__) __r;              \
        BPF_CORE_READ_INTO(&__r, (src), a, ##__VA_ARGS__); \
        __r;                                               \
    })

#endif

// helper macros for branch prediction
#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif