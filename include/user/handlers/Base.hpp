#pragma once
#include "common.hpp"
#include <atomic>
#include <bpf/libbpf.h>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

template <class T> struct CallBackContext {
    T *self;
    const char *tag;
};

class BaseHandler {

  protected:
    std::string _name;
    int _timeout_ms;
    std::atomic<bool> _running;
    std::atomic<uint64_t> _read_events;
    std::thread _poll_thread;
    std::mutex _mtx;
    std::vector<Event> _events;

    bpf_object *_obj{nullptr};

    // common link and buffer for when handler requires a single link or buffer
    static constexpr int CFG_OFFSET    = 0;
    static constexpr int EV_OFFSET     = 1;
    static constexpr int RB_OFFSET     = 2;
    static constexpr int RB_IN_OFFSET  = 3;
    static constexpr int RB_OUT_OFFSET = 3;
    std::vector<int> _map_buffers;

    std::vector<bpf_link *> _link;
    std::vector<ring_buffer *> _ring_buffers;

    void setRingBuffers(ring_buffer *rb1, ring_buffer *rb2);
    static int setCfgEnabledMap(int fd);
    static int freezeCfgEnabledMap(int fd);

    [[nodiscard]] uint64_t getSnapshotEVCountPerCPU(int fd) const;
    [[nodiscard]] static std::filesystem::path resolveBpfObjectPath(const std::string &obj_name);

    virtual void onSample(void *data, size_t len) = 0;

  public:
    explicit BaseHandler(std::string name, int poll_timeout_ms = 100);

    virtual ~BaseHandler();

    virtual bool install() = 0;
    virtual void detach() {}
    virtual void freezeProducer() {}
    virtual void stop();
    void start();

    virtual uint64_t snapshotTotal() { return _read_events.load(); }
    void drainUntil(uint64_t total_expected) const;
    std::vector<Event> collect();

    static std::string humanTs(uint64_t ts_ns);

    [[nodiscard]] const std::string &getName() const;
};
