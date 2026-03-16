#include "handlers/Clone3.hpp"
#include "shared_data_struct.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <climits>
#include <cstring>
#include <iostream>
#include <libgen.h>
#include <unistd.h>

Clone3Handler::Clone3Handler(const int poll_timeout_ms) : BaseHandler("fork", poll_timeout_ms) {}

Clone3Handler::~Clone3Handler() {
    stop();
    detach();
    if (_obj) {
        bpf_object__close(_obj);
    }
}

void Clone3Handler::stop() { BaseHandler::stop(); }

int Clone3Handler::sample_cb(void *ctx, void *data, const size_t len) {
    const auto *c = static_cast<CallBackContext<Clone3Handler> *>(ctx);
    c->self->onSample(c->tag, data, len);
    return 0;
}

bool Clone3Handler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    bpf_object_open_opts opts{};
    opts.sz              = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    std::string objp = resolveBpfObjectPath(_obj_name);
    _obj             = bpf_object__open_file(objp.c_str(), &opts);
    if (!_obj) {
        fprintf(stderr, "[clone3] open_file failed: %s\n", objp.c_str());
        return false;
    }

    if (const int err = bpf_object__load(_obj); err) {
        const char *libbpf_err = strerror(-err);
        fprintf(stderr, "[clone3] load failed: %s (err=%d)\n", libbpf_err ? libbpf_err : "unknown",
                err);
        return false;
    }

    _map_buffers[CFG_OFFSET] = bpf_object__find_map_fd_by_name(_obj, "cfg_enabled");
    _map_buffers[EV_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "ev_count");
    _map_buffers[RB_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "clone3_output");
    if (_map_buffers[CFG_OFFSET] < 0 || _map_buffers[EV_OFFSET] < 0 ||
        _map_buffers[RB_OFFSET] < 0) {
        fprintf(stderr, "[clone3] missing maps (cfg_enabled/ev_count/clone3_output)\n");
        return false;
    }

    auto *prog = bpf_object__find_program_by_name(_obj, "trace_clone3_exit");
    if (!prog) {
        fprintf(stderr, "[clone3] program trace_clone3_exit not found\n");
        return false;
    }
    _link[0] = bpf_program__attach_tracepoint(prog, "syscalls", "sys_exit_clone3");
    if (!_link[0]) {
        fprintf(stderr, "[clone3] attach sys_exit_clone3 failed: %s\n", strerror(errno));
        return false;
    }

    setCfgEnabledMap(_map_buffers[CFG_OFFSET]);

    _rb_ctx          = {this, "fork"};
    _ring_buffers[0] = ring_buffer__new(_map_buffers[RB_OFFSET], sample_cb, &_rb_ctx, nullptr);
    if (!_ring_buffers[0]) {
        fprintf(stderr, "[clone3] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void Clone3Handler::detach() {
    if (_link[0]) {
        bpf_link__destroy(_link[0]);
        _link[0] = nullptr;
    }
    if (_ring_buffers[0]) {
        ring_buffer__free(_ring_buffers[0]);
        _ring_buffers[0] = nullptr;
    }
}

void Clone3Handler::freezeProducer() { freezeCfgEnabledMap(_map_buffers[CFG_OFFSET]); }

uint64_t Clone3Handler::snapshotTotal() {
    return getSnapshotEVCountPerCPU(_map_buffers[EV_OFFSET]);
}

void Clone3Handler::onSample(void *data, size_t len) { onSample("fork", data, len); }

void Clone3Handler::onSample(const char *tag, const void *data, const size_t len) {
    if (len < sizeof(data_t)) {
        return;
    }
    _read_events.fetch_add(1, std::memory_order_relaxed);
    auto *ev = static_cast<const data_t *>(data);

    Event e;
    e.event           = tag ? std::string(tag) : std::string("fork");
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
