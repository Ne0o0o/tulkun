#ifndef __COMMON_BUFFER_H__
#define __COMMON_BUFFER_H__

#include <maps.h>

#include <vmlinux.h>

static __always_inline buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline int save_bytes_to_buf(buffer_data_t *buffer, void *ptr, u32 size)
{
    // Data saved to submit buf: [index][size][ ... bytes ... ]

    if (size == 0)
        return 0;

    // if (buffer->buf_off > MAX_BUF_SIZE - 1)
    //     return 0;

    // Save argument index
    // event->args[event->buf_off] = index;

    if (buffer->buf_off > MAX_BUF_SIZE - (sizeof(int) + 1))
        return 0;

    // Save size to buffer
    if (bpf_probe_read(&(buffer->buf[buffer->buf_off]), sizeof(int), &size) != 0)
    {
        return 0;
    }

    if (buffer->buf_off > MAX_BUF_SIZE - (MAX_BYTES_ARR_SIZE + sizeof(int)))
        return 0;

    // Read bytes into buffer
    if (bpf_probe_read(&(buffer->buf[buffer->buf_off + sizeof(int)]),
                       size & (MAX_BYTES_ARR_SIZE - 1),
                       ptr) == 0)
    {
        // We update buf_off only if all writes were successful
        buffer->buf_off += size + sizeof(int);
        // event->context.argnum++;
        buffer->arg_num++;
        return 1;
    }

    return 0;
}

static __always_inline int save_str_arr_to_buf(buffer_data_t *buffer, const char __user *const __user *ptr)
{
    // Data saved to submit buf: [string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;
    if (buffer->buf_off > MAX_BUF_SIZE - 1)
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

        if (buffer->buf_off > MAX_BUF_SIZE - MAX_STRING_LEN - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz =
            bpf_probe_read_str(&(buffer->buf[buffer->buf_off + sizeof(int)]), MAX_STRING_LEN, argp);
        if (sz > 0)
        {
            if (buffer->buf_off > MAX_BUF_SIZE - sizeof(int))
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
    if (orig_off > MAX_BUF_SIZE - 1)
        return 0;
    buffer->buf[orig_off] = elem_num;
    buffer->arg_num++;
    return 1;
}

#endif