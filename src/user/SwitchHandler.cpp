#include "handlers/Switch.hpp"
#include "shared_data_struct.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <string>

constexpr int FORK_OFFSET   = 0;
constexpr int SWITCH_OFFSET = 1;

static int sample_cb(void *ctx, void *data, size_t len) {
    static_cast<SwitchHandler *>(ctx)->onSample(data, len);
    return 0;
}

static void add_tid_if_any(const int map_allow_fd, const uint32_t tid) {
    if (!tid) {
        return;
    }
    bpf_map_update_elem(map_allow_fd, &tid, &ONE, BPF_ANY);
}

static void add_all_threads_of_pid(const int map_allow_fd, const uint32_t pid) {
    if (!pid) {
        return;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/task", pid);
    DIR *d = opendir(path);
    if (!d) {
        add_tid_if_any(map_allow_fd, pid);
        return;
    }
    dirent *de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') {
            continue;
        }
        if (const unsigned long tid = strtoul(de->d_name, nullptr, 10);
            tid > 0 && tid <= 0xfffffffful) {
            add_tid_if_any(map_allow_fd, static_cast<uint32_t>(tid));
        }
    }
    closedir(d);
}

SwitchHandler::SwitchHandler(const int poll_timeout_ms)
    : BaseHandler("switch", poll_timeout_ms), _shell_pid_hint(0), _cmd_pid_hint(0) {}

SwitchHandler::~SwitchHandler() {
    stop();
    detach();
    if (_obj) {
        bpf_object__close(_obj);
    }
}

bool SwitchHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    bpf_object_open_opts opts{};
    opts.sz              = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    const std::string objp = resolveBpfObjectPath(_obj_name);
    _obj                   = bpf_object__open_file(objp.c_str(), &opts);
    if (!_obj) {
        fprintf(stderr, "[switch] open_file failed: %s\n", objp.c_str());
        return false;
    }
    if (const int err = bpf_object__load(_obj)) {
        fprintf(stderr, "[switch] load failed: %s\n", strerror(-err));
        return false;
    }

    _map_buffers[CFG_OFFSET] = bpf_object__find_map_fd_by_name(_obj, "cfg_enabled");
    _map_buffers[EV_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "ev_count");
    _map_buffers[RB_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "sched_output");

    const int map_allow_ = bpf_object__find_map_fd_by_name(_obj, "allow_pids");
    const int map_usef_  = bpf_object__find_map_fd_by_name(_obj, "cfg_useFilter");
    if (_map_buffers[CFG_OFFSET] < 0 || _map_buffers[EV_OFFSET] < 0 ||
        _map_buffers[RB_OFFSET] < 0 || map_allow_ < 0 || map_usef_ < 0) {
        fprintf(stderr, "[switch] missing maps\n");
        return false;
    }

    {
        constexpr uint32_t k  = 0;
        constexpr uint32_t on = 1;
        if (bpf_map_update_elem(map_usef_, &k, &on, BPF_ANY) != 0) {
            fprintf(stderr, "[switch] failed to enable pid filter\n");
        }
    }

    if (!_shell_pid_hint && !_cmd_pid_hint) {
        uint32_t k = 0, off = 0;
        if (bpf_map_update_elem(map_usef_, &k, &off, BPF_ANY) != 0) {
            fprintf(stderr, "[switch] failed to disable pid filter\n");
        }
    } else {
        if (_shell_pid_hint) {
            add_tid_if_any(map_allow_, _shell_pid_hint);
        }
        if (_cmd_pid_hint) {
            add_tid_if_any(map_allow_, _cmd_pid_hint);
            add_all_threads_of_pid(map_allow_, _cmd_pid_hint);
            fprintf(stderr, "[switch] allow tgid=%u and its threads\n", _cmd_pid_hint);
        }
    }

    const bpf_program *prog = bpf_object__find_program_by_name(_obj, "trace_sched_switch");
    if (!prog) {
        fprintf(stderr, "[switch] program not found\n");
        return false;
    }
    _link[SWITCH_OFFSET] = bpf_program__attach_tracepoint(prog, "sched", "sched_switch");
    if (!_link[SWITCH_OFFSET]) {
        fprintf(stderr, "[switch] attach failed: %s\n", strerror(errno));
        return false;
    }

    const bpf_program *fork_prog =
        bpf_object__find_program_by_name(_obj, "propagate_allow_on_fork");
    if (!fork_prog) {
        fprintf(stderr, "[switch] fork program not found\n");
        return false;
    }
    _link[FORK_OFFSET] = bpf_program__attach_tracepoint(fork_prog, "sched", "sched_process_fork");
    if (!_link[FORK_OFFSET]) {
        fprintf(stderr, "[switch] fork attach failed: %s\n", strerror(errno));
        return false;
    }

    setCfgEnabledMap(_map_buffers[CFG_OFFSET]);

    _ring_buffers[0] = ring_buffer__new(_map_buffers[RB_OFFSET], sample_cb, this, nullptr);
    if (!_ring_buffers[0]) {
        fprintf(stderr, "[switch] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void SwitchHandler::detach() {
    if (_link[SWITCH_OFFSET]) {
        bpf_link__destroy(_link[SWITCH_OFFSET]);
        _link[SWITCH_OFFSET] = nullptr;
    }
    if (_link[FORK_OFFSET]) {
        bpf_link__destroy(_link[FORK_OFFSET]);
        _link[FORK_OFFSET] = nullptr;
    }
}

void SwitchHandler::stop() { BaseHandler::stop(); }

void SwitchHandler::freezeProducer() { freezeCfgEnabledMap(_map_buffers[CFG_OFFSET]); }

uint64_t SwitchHandler::snapshotTotal() {
    return getSnapshotEVCountPerCPU(_map_buffers[EV_OFFSET]);
}

void SwitchHandler::onSample(void *data, const size_t len) {
    if (len < sizeof(run_event_t)) {
        return;
    }
    _read_events.fetch_add(1, std::memory_order_relaxed);
    const auto *ev = static_cast<const run_event_t *>(data);

    Event e;
    e.event           = (ev->type == 1) ? "run" : "desched";
    e.pid             = ev->pid;
    e.cpu             = ev->cpu;
    e.reason          = (ev->reason == 1) ? "preempt" : "sleep";
    e.command         = std::string(ev->comm);
    e.timestamp       = ev->ts;
    e.timestamp_human = humanTs(ev->ts);

    std::lock_guard lk(_mtx);
    _events.push_back(std::move(e));
}

void SwitchHandler::setRootPid(const uint32_t shell_pid, const uint32_t cmd_pid) {
    _shell_pid_hint = shell_pid;
    _cmd_pid_hint   = cmd_pid;
}