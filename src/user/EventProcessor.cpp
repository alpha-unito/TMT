#include "processors/EventProcessor.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

struct Node {
    uint32_t pid;
    std::string command;
    bool alive{false};
    std::vector<Node> children;

    Node(const uint32_t pid_, const std::string &cmd_, const bool alive_ = false)
        : pid(pid_), command(cmd_), alive(alive_) {}

    [[nodiscard]] int size() const {
        int total = 1;
        for (const auto &c : children) {
            total += c.size();
        }
        return total;
    }

    [[nodiscard]] int compute_alive() const {
        if (!alive) {
            return 0;
        }
        int total = 1;
        for (const auto &c : children) {
            total += c.compute_alive();
        }
        return total;
    }

    void set_alive(uint32_t target_pid) {
        if (pid == target_pid) {
            alive = true;
            return;
        }
        for (auto &c : children) {
            c.set_alive(target_pid);
        }
    }

    void kill_all() {
        alive = false;
        for (auto &c : children) {
            c.kill_all();
        }
    }

    void set_dead(uint32_t target_pid) {
        if (pid == target_pid) {
            kill_all();
        } else {
            for (auto &c : children) {
                c.set_dead(target_pid);
            }
        }
    }

    bool add_child(const Event &e) {
        if (e.event == "fork" || e.event == "clone" || e.event == "clone3") {
            if (e.pid == pid) {
                children.emplace_back(e.child_pid, e.command);
                return true;
            }
            for (auto &c : children) {
                if (c.add_child(e)) {
                    return true;
                }
            }
        }
        return false;
    }
};

EventProcessor::~EventProcessor() = default;

EventProcessor::EventProcessor(const std::vector<Event> &evs, uint32_t root_pid)
    : _events(evs), _root_pid_hint(root_pid) {
    if (_events.empty()) {
        return;
    }

    root_pid              = _root_pid_hint;
    std::string root_comm = "[unknown]";

    if (root_pid == 0) {
        root_pid  = _events.front().pid;
        root_comm = _events.front().command;
    } else {
        for (const auto &e : _events) {
            if (e.pid == root_pid) {
                root_comm = e.command;
                break;
            }
        }
    }

    _root = std::make_unique<Node>(root_pid, root_comm, true);
}

void EventProcessor::buildTree(bool print_tree) {
    std::cerr << "[WARN] Building process tree...\n";
    if (!_root) {
        return;
    }

    for (const auto &e : _events) {
        _root->add_child(e);
    }

    std::cerr << "[INFO] Tree built successfully.\n";

    if (print_tree) {
        printTreeRec(*_root, 0);
    }
}

void EventProcessor::printTreeRec(const Node &n, int depth) {
    for (int i = 0; i < depth; ++i) {
        std::cerr << "  ";
    }
    std::cerr << n.command << " (" << n.pid << ")";
    if (n.alive) {
        std::cerr << " [ALIVE]";
    }
    std::cerr << "\n";
    for (const auto &c : n.children) {
        printTreeRec(c, depth + 1);
    }
}

void EventProcessor::computeIntervals(bool print_intervals) {
    std::cerr << "[WARN] Computing timestamp intervals...\n";
    if (!_root) {
        return;
    }

    std::vector<const Event *> evp;
    evp.reserve(_events.size());
    for (auto &e : _events) {
        evp.push_back(&e);
    }

    std::sort(evp.begin(), evp.end(),
              [](const Event *a, const Event *b) { return a->timestamp < b->timestamp; });

    _time_intervals.clear();

    uint64_t max_ts = 0;

    for (const auto *e : evp) {
        if (e->timestamp > max_ts) {
            max_ts = e->timestamp;
        }

        if (e->event == "fork" || e->event == "clone" || e->event == "clone3") {
            _root->set_alive(e->child_pid);
        } else if (e->event == "exit") {
            _root->set_dead(e->pid);
        } else if (e->event == "exit_group") {
            _root->set_dead(e->parent_pid);
        }

        if (const int alive = _root->compute_alive();
            _time_intervals.empty() || _time_intervals.back().alive != alive) {
            _time_intervals.push_back({e->timestamp, alive});
        }
    }

    if (!_time_intervals.empty() && _time_intervals.back().time < max_ts) {
        const int last_alive = _time_intervals.back().alive;
        _time_intervals.push_back({max_ts, last_alive});
    }

    std::cerr << "[INFO] Computed " << _time_intervals.size() << " time intervals.\n";
    if (print_intervals) {
        std::cerr << "time,alive\n";
        for (const auto &t : _time_intervals) {
            std::cerr << t.time << "," << t.alive << "\n";
        }
    }
}

void EventProcessor::storeToCsv(const std::string &filename) const {
    std::ofstream f(filename);
    f << "time,alive\n";
    for (const auto &[time, alive] : _time_intervals) {
        f << time << "," << alive << "\n";
    }
    f.close();
    std::cerr << "[INFO] Saved CSV to " << filename << "\n";
}
