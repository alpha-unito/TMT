#include "handlers/Exit.hpp"
#include "shared_data_struct.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <libgen.h>

ExitHandler::ExitHandler(const int poll_timeout_ms) : BaseHandler("exit", poll_timeout_ms) {}

ExitHandler::~ExitHandler() {
    stop();
    detach();
    if (_obj) {
        bpf_object__close(_obj);
    }
}

void ExitHandler::stop() { BaseHandler::stop(); }

static int sample_cb(void *ctx, void *data, const size_t len) {
    const auto *c = static_cast<CallBackContext<ExitHandler> *>(ctx);
    c->self->onSample(c->tag, data, len);
    return 0;
}

bool ExitHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    bpf_object_open_opts opts{};
    opts.sz              = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    const std::string objp = resolveBpfObjectPath(_obj_name);
    _obj                   = bpf_object__open_file(objp.c_str(), &opts);
    if (!_obj) {
        fprintf(stderr, "[exit] open_file failed: %s\n", objp.c_str());
        return false;
    }

    if (const int err = bpf_object__load(_obj)) {
        fprintf(stderr, "[exit] load failed: %s\n", strerror(-err));
        return false;
    }

    _map_buffers[CFG_OFFSET] = bpf_object__find_map_fd_by_name(_obj, "cfg_enabled");
    _map_buffers[EV_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "ev_count");
    _map_buffers[RB_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "exit_output");

    if (_map_buffers[CFG_OFFSET] < 0 || _map_buffers[EV_OFFSET] < 0 ||
        _map_buffers[RB_OFFSET] < 0) {
        fprintf(stderr, "[exit] missing maps (cfg_enabled/ev_count/exit_output)\n");
        return false;
    }

    const bpf_program *exit_prog = bpf_object__find_program_by_name(_obj, "trace_exit_enter");
    if (!exit_prog) {
        fprintf(stderr, "[exit] program 'trace_exit_enter' not found in obj\n");
        return false;
    }

    _link[0] = bpf_program__attach_tracepoint(exit_prog, "syscalls", "sys_enter_exit");
    if (!_link[0]) {
        fprintf(stderr, "[exit] attach sys_enter_exit failed: %s\n", strerror(errno));
        return false;
    }

    setCfgEnabledMap(_map_buffers[CFG_OFFSET]);

    _rb_exit_ctx     = {this, "exit"};
    _ring_buffers[0] = ring_buffer__new(_map_buffers[RB_OFFSET], sample_cb, &_rb_exit_ctx, nullptr);
    if (!_ring_buffers[0]) {
        fprintf(stderr, "[exit] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void ExitHandler::detach() {
    if (_link[0]) {
        bpf_link__destroy(_link[0]);
        _link[0] = nullptr;
    }
}

void ExitHandler::freezeProducer() { freezeCfgEnabledMap(_map_buffers[CFG_OFFSET]); }

uint64_t ExitHandler::snapshotTotal() { return getSnapshotEVCountPerCPU(_map_buffers[EV_OFFSET]); }

void ExitHandler::onSample(void *data, size_t len) { onSample("exit", data, len); }

void ExitHandler::onSample(const char *tag, void *data, size_t len) {
    if (len < sizeof(data_t)) {
        return;
    }
    _read_events.fetch_add(1, std::memory_order_relaxed);
    auto *ev = static_cast<const data_t *>(data);

    Event e;
    e.event           = tag ? std::string(tag) : std::string("exit");
    e.parent_pid      = ev->parent_pid;
    e.pid             = ev->pid;
    e.child_pid       = ev->child_pid;
    e.pgid            = ev->pgid;
    e.tid             = ev->tid;
    e.tgid            = ev->tgid;
    e.command         = std::string(ev->command);
    e.timestamp       = ev->timestamp;
    e.timestamp_human = BaseHandler::humanTs(ev->timestamp);

    std::lock_guard lk(_mtx);
    _events.push_back(std::move(e));
}
