// SPDX-License-Identifier: BSD-3-Clause
#ifndef BPFHIJACK_H
#define BPFHIJACK_H

#define TASK_COMM_LEN 16
#define BPF_OBJ_NAME_LEN 16
struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    char prog_name[BPF_OBJ_NAME_LEN];
    u32 insn_cnt;
    bool target;
    bool zeroed;
};

#endif  // BPFHIJACK_H
