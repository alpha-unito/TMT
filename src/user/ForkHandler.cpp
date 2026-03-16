#include "handlers/Fork.hpp"
#include "shared_data_struct.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <libgen.h>
#include <unistd.h>

ForkHandler::ForkHandler(const int poll_timeout_ms) : BaseHandler("fork", poll_timeout_ms) {}

ForkHandler::~ForkHandler() {
    stop();
    detach();
    if (_obj) {
        bpf_object__close(_obj);
    }
}

static int sample_cb(void *ctx, void *data, const size_t len) {
    const auto *c = static_cast<CallBackContext<ForkHandler> *>(ctx);
    c->self->onSample(c->tag, data, len);
    return 0;
}

bool ForkHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    bpf_object_open_opts opts{};
    opts.sz              = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    std::string objp = resolveBpfObjectPath(_obj_name);
    _obj             = bpf_object__open_file(objp.c_str(), &opts);
    if (!_obj) {
        fprintf(stderr, "[fork] open_file failed: %s\n", objp.c_str());
        return false;
    }
    int err = bpf_object__load(_obj);
    if (err) {
        const char *libbpf_err = strerror(-err);
        fprintf(stderr, "[fork] load failed: %s (err=%d)\n", libbpf_err ? libbpf_err : "unknown",
                err);
        return false;
    }

    _map_buffers[CFG_OFFSET] = bpf_object__find_map_fd_by_name(_obj, "cfg_enabled");
    _map_buffers[EV_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "ev_count");
    _map_buffers[RB_OFFSET]  = bpf_object__find_map_fd_by_name(_obj, "fork_output");
    if (_map_buffers[CFG_OFFSET] < 0 || _map_buffers[EV_OFFSET] < 0 ||
        _map_buffers[RB_OFFSET] < 0) {
        fprintf(stderr, "[fork] missing maps (cfg_enabled/ev_count/fork_output)\n");
        return false;
    }

    bpf_program *fork_prog = bpf_object__find_program_by_name(_obj, "handle_sched_fork");
    if (!fork_prog) {
        fprintf(stderr, "[fork] program trace_fork_exit not found in obj\n");
        return false;
    }
    _link[0] = bpf_program__attach_tracepoint(fork_prog, "sched", "sched_process_fork");
    if (!_link[0]) {
        fprintf(stderr, "[fork] attach sys_exit_fork failed: %s\n", strerror(errno));
        return false;
    }

    setCfgEnabledMap(_map_buffers[CFG_OFFSET]);

    _rb_fork_ctx     = {this, "fork"};
    _ring_buffers[0] = ring_buffer__new(_map_buffers[RB_OFFSET], sample_cb, &_rb_fork_ctx, NULL);
    if (!_ring_buffers[0]) {
        fprintf(stderr, "[fork] ring_buffer__new failed\n");
        return false;
    }

    fprintf(stderr, "[fork] Handler installed successfully!\n");
    start();
    return true;
}

void ForkHandler::detach() {
    if (_link[0]) {
        bpf_link__destroy(_link[0]);
        _link[0] = nullptr;
    }
}

void ForkHandler::stop() { BaseHandler::stop(); }

void ForkHandler::freezeProducer() { freezeCfgEnabledMap(_map_buffers[CFG_OFFSET]); }

uint64_t ForkHandler::snapshotTotal() { return getSnapshotEVCountPerCPU(_map_buffers[EV_OFFSET]); }

void ForkHandler::onSample(void *data, const size_t len) { onSample("fork", data, len); }

void ForkHandler::onSample(const char *tag, void *data, const size_t len) {
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
