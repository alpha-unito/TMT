#include "handlers/Clone.hpp"
#include "shared_data_struct.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>

CloneHandler::CloneHandler(int poll_timeout_ms) : BaseHandler("fork", poll_timeout_ms) {}

CloneHandler::~CloneHandler() {
    stop();
    detach();
    if (_obj) {
        bpf_object__close(_obj);
    }
}

int CloneHandler::sample_cb(void *ctx, void *data, size_t len) {
    const auto *c = static_cast<CallBackContext<CloneHandler> *>(ctx);
    c->self->onSample(c->tag, data, len);
    return 0;
}

bool CloneHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    bpf_object_open_opts opts{};
    opts.sz              = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    const std::string objp = resolveBpfObjectPath(_obj_name);
    _obj                   = bpf_object__open_file(objp.c_str(), &opts);
    if (!_obj) {
        fprintf(stderr, "[clone] open_file failed: %s\n", objp.c_str());
        return false;
    }
    int err = bpf_object__load(_obj);
    if (err) {
        const char *libbpf_err = strerror(-err);
        fprintf(stderr, "[clone] load failed: %s (err=%d)\n", libbpf_err ? libbpf_err : "unknown",
                err);
        return false;
    }

    _map_buffers[CFG_OFFSET] = bpf_object__find_map_fd_by_name(_obj, "cfg_enabled");
    _map_buffers[EV_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "ev_count");
    _map_buffers[RB_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "clone_output");
    if (_map_buffers[CFG_OFFSET] < 0 || _map_buffers[EV_OFFSET] < 0 ||
        _map_buffers[RB_OFFSET] < 0) {
        fprintf(stderr, "[clone] missing maps (cfg_enabled/ev_count/clone_output)\n");
        return false;
    }

    auto *prog = bpf_object__find_program_by_name(_obj, "trace_clone_exit");
    if (!prog) {
        fprintf(stderr, "[clone] program trace_clone_exit not found\n");
        return false;
    }
    _link[0] = bpf_program__attach_tracepoint(prog, "syscalls", "sys_exit_clone");
    if (!_link[0]) {
        fprintf(stderr, "[clone] attach sys_exit_clone failed: %s\n", strerror(errno));
        return false;
    }

    setCfgEnabledMap(_map_buffers[EV_OFFSET]);

    _rb_ctx          = {this, "fork"};
    _ring_buffers[0] = ring_buffer__new(_map_buffers[RB_OFFSET], sample_cb, &_rb_ctx, NULL);
    if (!_ring_buffers[0]) {
        fprintf(stderr, "[clone] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void CloneHandler::detach() {
    if (_link[0]) {
        bpf_link__destroy(_link[0]);
        _link[0] = nullptr;
    }
    if (_ring_buffers[0]) {
        ring_buffer__free(_ring_buffers[0]);
        _ring_buffers[0] = nullptr;
    }
}

void CloneHandler::stop() { BaseHandler::stop(); }

void CloneHandler::freezeProducer() { freezeCfgEnabledMap(_map_buffers[CFG_OFFSET]); }

uint64_t CloneHandler::snapshotTotal() { return getSnapshotEVCountPerCPU(_map_buffers[EV_OFFSET]); }

void CloneHandler::onSample(void *data, size_t len) { onSample("fork", data, len); }

int CloneHandler::onSample(const char *tag, void *data, size_t len) {
    if (len < sizeof(data_t)) {
        return 0;
    }
    _read_events.fetch_add(1, std::memory_order_relaxed);
    auto *ev = (const data_t *) data;

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
    e.timestamp_human = BaseHandler::humanTs(ev->timestamp);

    std::lock_guard<std::mutex> lk(_mtx);
    _events.push_back(std::move(e));
    return 0;
}
