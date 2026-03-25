#include "handlers/ExitGroup.hpp"
#include "shared_data_struct.h"
#include <bpf/bpf.h>
#include <climits>
#include <cstring>
#include <iostream>
#include <libgen.h>
#include <unistd.h>

static int sample_cb(void *ctx, void *data, const size_t len) {
    static_cast<ExitGroupHandler *>(ctx)->onSample(data, len);
    return 0;
}

ExitGroupHandler::ExitGroupHandler(int poll_timeout_ms)
    : BaseHandler("exit_group", poll_timeout_ms) {}

ExitGroupHandler::~ExitGroupHandler() {
    stop();
    detach();
    if (_obj) {
        bpf_object__close(_obj);
    }
}

bool ExitGroupHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    bpf_object_open_opts opts{};
    opts.sz              = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    const std::string objp = resolveBpfObjectPath(_obj_name);
    _obj             = bpf_object__open_file(objp.c_str(), &opts);
    if (!_obj) {
        fprintf(stderr, "[exit_group] open_file failed: %s\n", objp.c_str());
        return false;
    }

    int err = bpf_object__load(_obj);
    if (err) {
        fprintf(stderr, "[exit_group] load failed: %s\n", strerror(-err));
        return false;
    }

    _map_buffers[CFG_OFFSET] = bpf_object__find_map_fd_by_name(_obj, "cfg_enabled");
    _map_buffers[EV_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "ev_count");
    _map_buffers[RB_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "exit_group_output");

    if (_map_buffers[CFG_OFFSET] < 0 || _map_buffers[EV_OFFSET] < 0 ||
        _map_buffers[RB_OFFSET] < 0) {
        fprintf(stderr, "[exit_group] missing maps\n");
        return false;
    }

    bpf_program *prog = bpf_object__find_program_by_name(_obj, "trace_exit_group");
    if (!prog) {
        fprintf(stderr, "[exit_group] program not found\n");
        return false;
    }

    _link[0] = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_exit_group");
    if (!_link[0]) {
        fprintf(stderr, "[exit_group] attach failed: %s\n", strerror(errno));
        return false;
    }

    setCfgEnabledMap(_map_buffers[CFG_OFFSET]);

    _ring_buffers[0] = ring_buffer__new(_map_buffers[RB_OFFSET], sample_cb, this, nullptr);
    if (!_ring_buffers[0]) {
        fprintf(stderr, "[exit_group] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void ExitGroupHandler::stop() { BaseHandler::stop(); }

void ExitGroupHandler::detach() {
    if (_link[0]) {
        bpf_link__destroy(_link[0]);
        _link[0] = nullptr;
    }
}

void ExitGroupHandler::freezeProducer() { freezeCfgEnabledMap(_map_buffers[CFG_OFFSET]); }

uint64_t ExitGroupHandler::snapshotTotal() {
    return getSnapshotEVCountPerCPU(_map_buffers[EV_OFFSET]);
}

void ExitGroupHandler::onSample(void *data, size_t len) {
    if (len < sizeof(data_t)) {
        return;
    }
    _read_events.fetch_add(1, std::memory_order_relaxed);
    const auto ev = static_cast<const data_t *>(data);

    Event e;
    e.event           = "exit_group";
    e.parent_pid      = ev->parent_pid;
    e.pid             = ev->pid;
    e.child_pid       = ev->child_pid;
    e.pgid            = ev->pgid;
    e.tid             = ev->tid;
    e.tgid            = ev->tgid;
    e.command         = std::string(ev->command);
    e.timestamp       = ev->timestamp;
    e.timestamp_human = humanTs(ev->timestamp);

    std::lock_guard lk(_mtx);
    _events.push_back(std::move(e));
}
