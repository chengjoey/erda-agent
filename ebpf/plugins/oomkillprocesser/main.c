#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/oom.h>
#include <linux/cgroup.h>
#include <linux/kernfs.h>
#include "../../include/common.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define MAX_STACK_RAWTP 50

#define SYM_LEN 50

struct oom_stats {
    // Pid of triggering process
    __u32 pid;
    char fcomm[TASK_COMM_LEN];
    __u32 cgroupid;
//    char cgroup_path[129];
    int user_stack_size;
    __u64 ustack[MAX_STACK_RAWTP];
};

static __always_inline int get_cgroup_name(char *buf, size_t sz) {
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return -1;
    }

    int cgrp_id = memory_cgrp_id;

    // failed when use BPF_PROBE_READ, but success when use BPF_CORE_READ
    const char *name = BPF_PROBE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);
    if (bpf_probe_read_kernel_str(buf, sz, name) < 0) {
        bpf_printk("failed to get kernfs node name: %s\n", buf);
        return -1;
    }
    bpf_printk("cgroup name: %s\n", buf);

    return 0;
}


struct bpf_map_def SEC("maps/package_map") oom_map = {
  	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct oom_stats),
	.max_entries = 1024 * 16,
};

SEC("kprobe/oom_kill_process")
int kprobe_oom_kill_process(struct pt_regs *ctx) {
    struct oom_control *oc = (struct oom_control *)PT_REGS_PARM1(ctx);
    struct task_struct *p;
    bpf_probe_read(&p, sizeof(p), &oc->chosen);
    if (!p) {
        return 0;
    }

    struct oom_stats data = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&oom_map, &pid, &data, BPF_NOEXIST);
    struct oom_stats *s = bpf_map_lookup_elem(&oom_map, &pid);
    if (!s) {
        bpf_map_update_elem(&oom_map, &pid, &data, BPF_ANY);
        return 0;
    }

    s->pid = pid;
    bpf_get_current_comm(&s->fcomm, sizeof(s->fcomm));
    __u32 cgroupid = bpf_get_current_cgroup_id();
    s->cgroupid = cgroupid;

    int max_len;
    max_len = MAX_STACK_RAWTP * sizeof(__u64);
    s->user_stack_size = bpf_get_stack(ctx, s->ustack, max_len, BPF_F_USER_STACK);

    bpf_printk("user stack: %llx, size: %d\n", s->ustack, s->user_stack_size);

//    if (get_cgroup_name(s->cgroup_path, sizeof(s->cgroup_path)) < 0) {
//        bpf_printk("failed to get cgroup name\n");
//        return -1;
//    }
//    get_dir_by_knid(cgroupid, s->cgroup_path, sizeof(s->cgroup_path));

//    char idfmt[] = "oom process cgroup knid: %d, pages: %d, name: %s\n";
//    bpf_trace_printk(idfmt, sizeof(idfmt), s->knid, s->pages, s->cgroup_path);
    return 0;
}


char _license[] SEC("license") = "GPL";