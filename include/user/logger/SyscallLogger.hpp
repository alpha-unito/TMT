#pragma once
#include "common.hpp"
#include "handlers/Base.hpp"
#include <memory>
#include <string>
#include <vector>

class SyscallLogger {
    std::vector<std::unique_ptr<BaseHandler>> _handlers;
    std::vector<Event> _events;
    int _timeout_ms;
    uint32_t _root_pid;

  public:
    explicit SyscallLogger(int timeout_ms = 100);

    [[nodiscard]] const std::vector<Event> &getEvents() const;
    [[nodiscard]] uint32_t getRootPid() const;
    [[nodiscard]] bool installAll() const;

    void stop();
    void runCommand(const std::string &cmd, bool print_raw = false);
};
