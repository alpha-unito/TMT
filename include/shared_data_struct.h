#pragma once

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef __u32
#define __u32 uint32_t
#endif

#ifndef __u64
#define __u64 uint64_t
#endif

#ifdef _USERSPACE
constexpr uint32_t KEY  = 0;
constexpr uint32_t ZERO = 0;
constexpr uint32_t ONE  = 1;
#endif

#ifdef _USERSPACE
#pragma pack(push, 1)
#endif
struct data_t {
    __u32 parent_pid;
    __u32 pid;
    __u32 child_pid; // ->! 0 on execve
    __u32 pgid;
    __u32 tid;
    __u32 tgid;
    char command[TASK_COMM_LEN];
    __u64 timestamp; // ns
};
#ifdef _USERSPACE
#pragma pack(pop)
#endif

#ifdef _USERSPACE
#pragma pack(push, 1)
#endif
struct run_event_t {
    __u64 ts;     // ns
    __u32 cpu;    // CPU id
    __u32 pid;    // PID of subject task
    __u32 type;   // 1: switch-in, 2: switch-out
    __u32 reason; // 0: runnable/yield, 1: blocked (prev_state != 0)
    char comm[TASK_COMM_LEN];
    __u32 parent_pid, child_pid, pgid, tid, tgid;
    char command[TASK_COMM_LEN];
    __u64 timestamp;
};
#ifdef _USERSPACE
#pragma pack(pop)
#endif