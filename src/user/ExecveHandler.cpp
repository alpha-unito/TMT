#include "handlers/Execve.hpp"
#include "shared_data_struct.h"
#include <bpf/bpf.h>
#include <climits>
#include <cstring>
#include <iostream>
#include <libgen.h>
#include <unistd.h>

constexpr int ENTER_OFFSET = 0;
constexpr int EXIT_OFFSET  = 1;

static int sample_cb(void *ctx, void *data, const size_t len) {
    const auto *c = static_cast<CallBackContext<ExecveHandler> *>(ctx);
    c->self->onSample(c->tag, data, len);
    return 0;
}

ExecveHandler::ExecveHandler(int poll_timeout_ms) : BaseHandler("execve", poll_timeout_ms) {}

ExecveHandler::~ExecveHandler() {
    stop();
    detach();
    if (_obj) {
        bpf_object__close(_obj);
    }
}



bool ExecveHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    bpf_object_open_opts opts{};
    opts.sz              = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    const std::string objp = resolveBpfObjectPath(_obj_name);
    _obj                   = bpf_object__open_file(objp.c_str(), &opts);
    if (!_obj) {
        fprintf(stderr, "[execve] open_file failed: %s\n", objp.c_str());
        return false;
    }
    if (const int err = bpf_object__load(_obj)) {
        const char *libbpf_err = strerror(-err);
        fprintf(stderr, "[execve] load failed: %s (err=%d)\n", libbpf_err ? libbpf_err : "unknown",
                err);
        return false;
    }

    _map_buffers[CFG_OFFSET]    = bpf_object__find_map_fd_by_name(_obj, "cfg_enabled");
    _map_buffers[EV_OFFSET]     = bpf_object__find_map_fd_by_name(_obj, "ev_count");
    _map_buffers[RB_IN_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "execve_output_in");
    _map_buffers[RB_OUT_OFFSET] = bpf_object__find_map_fd_by_name(_obj, "execve_output_out");
    if (_map_buffers[CFG_OFFSET] < 0 || _map_buffers[EV_OFFSET] < 0 ||
        _map_buffers[RB_IN_OFFSET] < 0 || _map_buffers[RB_OUT_OFFSET] < 0) {
        fprintf(stderr, "[execve] missing maps\n");
        return false;
    }

    bpf_program *enter_prog = bpf_object__find_program_by_name(_obj, "trace_execve");
    bpf_program *exit_prog  = bpf_object__find_program_by_name(_obj, "trace_execve_exit");
    if (!enter_prog || !exit_prog) {
        fprintf(stderr, "[execve] program not found by name\n");
        return false;
    }
    _link[ENTER_OFFSET] =
        bpf_program__attach_tracepoint(enter_prog, "syscalls", "sys_enter_execve");
    if (!_link[ENTER_OFFSET]) {
        fprintf(stderr, "[execve] attach enter failed: %s\n", strerror(errno));
        return false;
    }
    _link[EXIT_OFFSET] = bpf_program__attach_tracepoint(exit_prog, "syscalls", "sys_exit_execve");
    if (!_link[EXIT_OFFSET]) {
        fprintf(stderr, "[execve] attach exit failed: %s\n", strerror(errno));
        return false;
    }

    setCfgEnabledMap(_map_buffers[CFG_OFFSET]);

    _rb_in_ctx  = {this, "execve-entry"};
    _rb_out_ctx = {this, "execve-exit"};

    _ring_buffers[0] =
        ring_buffer__new(_map_buffers[RB_IN_OFFSET], sample_cb, &_rb_in_ctx, nullptr);
    _ring_buffers[1] =
        ring_buffer__new(_map_buffers[RB_OUT_OFFSET], sample_cb, &_rb_out_ctx, nullptr);
    if (!_ring_buffers[0] || !_ring_buffers[1]) {
        fprintf(stderr, "[execve] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void ExecveHandler::stop() { BaseHandler::stop(); }

void ExecveHandler::detach() {
    if (_link[ENTER_OFFSET]) {
        bpf_link__destroy(_link[ENTER_OFFSET]);
        _link[ENTER_OFFSET] = nullptr;
    }
    if (_link[EXIT_OFFSET]) {
        bpf_link__destroy(_link[EXIT_OFFSET]);
        _link[EXIT_OFFSET] = nullptr;
    }
}

void ExecveHandler::freezeProducer() { freezeCfgEnabledMap(_map_buffers[CFG_OFFSET]); }

uint64_t ExecveHandler::snapshotTotal() {
    return getSnapshotEVCountPerCPU(_map_buffers[EV_OFFSET]);
}

void ExecveHandler::onSample(const char *tag, const void *data, const size_t len) {
    if (len < sizeof(data_t)) {
        return;
    }
    _read_events.fetch_add(1, std::memory_order_relaxed);
    auto *ev = static_cast<const data_t *>(data);

    Event e;
    e.event           = tag ? std::string(tag) : std::string("execve");
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

// not used
void ExecveHandler::onSample(void *data, size_t len) { onSample("execve", data, len); }
