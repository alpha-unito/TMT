#include "handlers/Base.hpp"
#include "shared_data_struct.h"
#include <bpf/bpf.h>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <linux/limits.h>
#include <string>
#include <sys/sysinfo.h>
#include <unistd.h>

void BaseHandler::start() {
    _running.store(true);
    _poll_thread = std::thread([this]() {
        while (_running.load(std::memory_order_relaxed)) {
            if (_ring_buffers[0]) {
                if (const int ret = ring_buffer__poll(_ring_buffers[0], _timeout_ms);
                    ret < 0 && ret != -EINTR) {
                    fprintf(stderr, "[%s] rb1 poll err=%d\n", _name.c_str(), ret);
                }
            }
            if (_ring_buffers[1]) {
                if (const int ret = ring_buffer__poll(_ring_buffers[1], _timeout_ms);
                    ret < 0 && ret != -EINTR) {
                    fprintf(stderr, "[%s] rb2 poll err=%d\n", _name.c_str(), ret);
                }
            }
        }
    });
}

void BaseHandler::stop() {
    if (!_running.exchange(false)) {
        return;
    }
    if (_poll_thread.joinable()) {
        _poll_thread.join();
    }
    if (_ring_buffers[0]) {
        ring_buffer__free(_ring_buffers[0]);
        _ring_buffers[0] = nullptr;
    }
    if (_ring_buffers[1]) {
        ring_buffer__free(_ring_buffers[1]);
        _ring_buffers[1] = nullptr;
    }
}

void BaseHandler::drainUntil(const uint64_t total_expected) const {
    int idle = 0;
    while (_read_events.load() < total_expected) {
        if (_ring_buffers[0]) {
            ring_buffer__poll(_ring_buffers[0], 0);
        }
        if (_ring_buffers[1]) {
            ring_buffer__poll(_ring_buffers[1], 0);
        }
        if (constexpr int MAX_IDLE = 5000; ++idle > MAX_IDLE) {
            break;
        }
        usleep(1000);
    }
}

std::vector<Event> BaseHandler::collect() {
    std::lock_guard lk(_mtx);
    return _events;
}

void BaseHandler::setRingBuffers(ring_buffer *rb1, ring_buffer *rb2) {
    _ring_buffers[0] = rb1;
    _ring_buffers[1] = rb2;
}

int BaseHandler::setCfgEnabledMap(const int fd) {
    return bpf_map_update_elem(fd, &KEY, &ONE, BPF_ANY);
}

int BaseHandler::freezeCfgEnabledMap(const int fd) {
    return bpf_map_update_elem(fd, &KEY, &ZERO, BPF_ANY);
}

uint64_t BaseHandler::getSnapshotEVCountPerCPU(const int fd) const {
    const int n = libbpf_num_possible_cpus();
    std::vector<uint64_t> vals(n);
    constexpr uint32_t key = 0;
    if (bpf_map_lookup_elem(fd, &key, vals.data()) != 0) {
        return _read_events.load();
    }
    uint64_t tot = 0;
    for (const auto v : vals) {
        tot += v;
    }
    return tot;
}
const std::string &BaseHandler::getName() const { return _name; }

std::filesystem::path BaseHandler::resolveBpfObjectPath(const std::string &obj_name) {

    std::error_code ec;

    const std::filesystem::path exe_path = std::filesystem::read_symlink("/proc/self/exe", ec);

    if (!ec) {
        return exe_path.parent_path() / obj_name;
    }
    return std::filesystem::path("./bin/") / obj_name;
}

BaseHandler::BaseHandler(std::string name, const int poll_timeout_ms)
    : _name(std::move(name)), _timeout_ms(poll_timeout_ms), _running(false), _read_events(0),
      _map_buffers(5), _link(2), _ring_buffers(2) {}

BaseHandler::~BaseHandler() { stop(); }

std::string BaseHandler::humanTs(const uint64_t ts_ns) {
    struct sysinfo si{};
    sysinfo(&si);
    const time_t now  = time(nullptr);
    const time_t boot = now - si.uptime;
    const time_t sec  = boot + static_cast<time_t>(ts_ns / 1000000000ULL);
    tm tmv{};
    localtime_r(&sec, &tmv);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    char out[96];
    snprintf(out, sizeof(out), "%s.%06lu", buf,
             static_cast<unsigned long>((ts_ns / 1000ULL) % 1000000ULL));
    return {out};
}
