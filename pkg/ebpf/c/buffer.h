#include <vmlinux.h>

#define MAX_STR_ARR_ELEM 38  // TODO: turn this into global variables set w/ libbpfgo
#define MAX_STRING_SIZE 4096 // same as PATH_MAX
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)
#define ARGS_BUF_SIZE 128

typedef struct buffer
{
    u32 buf_off;
    char buf[ARGS_BUF_SIZE]
} buffer_data_t;

static __always_inline int save_str_arr_to_buf(buffer_data_t *buffer, const char __user *const __user *ptr)
{
    // Data saved to submit buf: [string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;
    if (buffer->buf_off > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    // event->args[event->buf_off] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = buffer->buf_off + 1;
    buffer->buf_off += 2;

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
    // handle truncated argument list
    char ellipsis[] = "...";
    if (buffer->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(buffer->args[buffer->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0)
    {
        if (event->buf_off > ARGS_BUF_SIZE - sizeof(int))
            // Satisfy validator
            goto out;
        bpf_probe_read(&(buffer->buf[buffer->buf_off]), sizeof(int), &sz);
        buffer->buf_off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    if (orig_off > ARGS_BUF_SIZE - 1)
        return 0;
    buffer->buf[orig_off] = elem_num;
    return 1;
}
