#pragma once
#include "../common.hpp"
#include <memory>
#include <string>
#include <vector>

#define TMT_DEBUG_INTERVALS 0

struct Node;

struct TimeInterval {
    uint64_t time;
    int alive;
};

class EventProcessor {

    std::vector<Event> _events;
    std::vector<TimeInterval> _time_intervals;
    std::unique_ptr<Node> _root;
    uint32_t _root_pid_hint = 0;

    static void printTreeRec(const Node &n, int depth);

  public:
    explicit EventProcessor(const std::vector<Event> &evs, uint32_t root_pid = 0);
    ~EventProcessor();

    void buildTree(bool print_tree = false);
    void computeIntervals(bool print_intervals = false);
    void storeToCsv(const std::string &filename = "out/alive_series.csv") const;
};
