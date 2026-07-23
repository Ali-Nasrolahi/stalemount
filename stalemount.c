// clang-format off
//go:build ignore

#include "vmlinux.h"

#include <linux/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// clang-format on

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, u32);
    __uint(max_entries, 1 << 14);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stalemount_active_opens SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, u32);
    __uint(max_entries, 1 << 14);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stalemount_policies SEC(".maps");

static __always_inline int check_file(struct file* file, bool opening)
{
    if (!file) return 0;

    struct mount* mnt = container_of(file->f_path.mnt, struct mount, mnt);
    if (!mnt) return 0;

    int mnt_id = BPF_CORE_READ(mnt, mnt_id);
    u32* open_count = bpf_map_lookup_elem(&stalemount_active_opens, &mnt_id);
    u32* policy = bpf_map_lookup_elem(&stalemount_policies, &mnt_id);

    if (open_count == NULL || policy == NULL) return 0;

    if (opening) {
        bpf_printk("OPEN mnt_id=%d\n", mnt_id);
        if (*policy) {
            bpf_printk("OPEN PERMISSION DENIED mnt_id=%d\n", mnt_id);
            return -EPERM;
        }
        __sync_fetch_and_add(open_count, 1);
    } else {
        bpf_printk("CLOSE mnt_id=%d\n", mnt_id);
        __sync_fetch_and_sub(open_count, 1);
    }

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsmopen, struct file* file, int ret)
{
    /*
     * Another LSM may already have rejected the open.
     */
    if (ret) return ret;

    return check_file(file, true);
}

SEC("fentry/__fput")
int BPF_PROG(kput, struct file* file)
{
    check_file(file, false);

    return 0;
}