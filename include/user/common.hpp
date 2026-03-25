#pragma once
#include <cstdint>
#include <string>

struct Event {
    std::string event;
    uint32_t parent_pid{0};
    uint32_t pid{0};
    uint32_t child_pid{0};
    uint32_t pgid{0};
    uint32_t tid{0};
    uint32_t tgid{0};
    uint32_t cpu{0};
    std::string command;
    uint64_t timestamp{0};
    std::string timestamp_human;
    std::string reason;
};

struct Slice {
    uint32_t pid;
    uint32_t cpu;
    std::string command;
    uint64_t start_ns;
    uint64_t end_ns;
    uint64_t delta_ns;
    std::string reason;
};