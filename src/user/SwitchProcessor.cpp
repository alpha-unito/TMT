#include "processors/SwitchProcessor.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>

// convert unit string to ns scale factor
static double unit_scale(const std::string &u) {
    if (u == "ns") {
        return 1.0;
    }
    if (u == "us") {
        return 1e3;
    }
    if (u == "ms") {
        return 1e6;
    }
    if (u == "s") {
        return 1e9;
    }
    throw std::invalid_argument("invalid time unit: " + u);
}

SwitchProcessor::SwitchProcessor(const std::vector<Event> &evs) : _events(evs) {
    _events.erase(
        std::remove_if(_events.begin(), _events.end(),
                       [](const Event &e) { return !(e.event == "run" || e.event == "desched"); }),
        _events.end());
}

void SwitchProcessor::buildSlices(bool debug) {
    std::cerr << "[SwitchProcessor] Processing " << _events.size() << " events\n";

    std::map<uint32_t, std::tuple<uint64_t, uint32_t, std::string>> open;
    _slices.clear();

    for (const auto &e : _events) {
        if (debug) {
            std::cerr << "[SwitchProcessor] Event: " << e.event << " pid=" << e.pid
                      << " cpu=" << e.cpu << " ts=" << e.timestamp << "\n";
        }

        uint32_t pid = e.pid;
        uint64_t ts  = e.timestamp;

        if (e.event == "run") {
            open[pid] = {ts, e.cpu, e.command};
        } else if (e.event == "desched") {
            if (auto it = open.find(pid); it != open.end()) {
                if (auto [start, cpu0, cmd0] = it->second; ts > start) {
                    Slice s{pid, cpu0, cmd0, start, ts, ts - start, e.reason};
                    _slices.push_back(std::move(s));
                }
                open.erase(it);
            }
        }
    }

    // close any pending slices at the end of trace
    if (!open.empty()) {
        uint64_t end_ts = 0;
        for (const auto &e : _events) {
            if (e.timestamp > end_ts) {
                end_ts = e.timestamp;
            }
        }

        for (auto &[pid, tup] : open) {
            auto [start, cpu0, cmd0] = tup;
            Slice s{pid, cpu0, cmd0, start, end_ts, end_ts - start, "end_of_trace"};
            _slices.push_back(std::move(s));
            std::cerr << "[SwitchProcessor] Closing pending slice for pid=" << pid << "\n";
        }
        open.clear();
    }

    std::cerr << "[SwitchProcessor] Built " << _slices.size() << " slices\n";
}

void SwitchProcessor::storeCsv(const std::string &filename) const {
    std::ofstream f(filename);
    f << "pid,cpu,command,start_ns,end_ns,delta_ns,reason\n";
    for (const auto &[pid, cpu, command, start_ns, end_ns, delta_ns, reason] : _slices) {
        f << pid << "," << cpu << "," << command << "," << start_ns << "," << end_ns << ","
          << delta_ns << "," << reason << "\n";
    }
    std::cerr << "[SwitchProcessor] Stored " << _slices.size() << " slices into " << filename
              << "\n";
}

void SwitchProcessor::plotTopRuntimePerCPU(const int top_n, const std::string &time_unit) const {
    if (_slices.empty()) {
        std::cerr << "[SwitchProcessor] No slices; nothing to plot\n";
        return;
    }

    double scale = unit_scale(time_unit);
    // aggregate total runtime per (cpu,pid,command)
    std::map<std::tuple<uint32_t, uint32_t, std::string>, uint64_t> agg;

    for (const auto &s : _slices) {
        auto key = std::make_tuple(s.cpu, s.pid, s.command);
        agg[key] += s.delta_ns;
    }

    // top per CPU
    std::map<uint32_t, std::vector<std::pair<std::string, double>>> per_cpu;
    for (const auto &[k, tot_ns] : agg) {
        auto [cpu, pid, cmd] = k;
        std::string label    = cmd + ":" + std::to_string(pid);
        per_cpu[cpu].emplace_back(label, tot_ns / static_cast<unsigned long>(scale));
    }

    std::cerr << "[SwitchProcessor] Top per-CPU runtime (unit=" << time_unit << ")\n";
    for (auto &[cpu, vec] : per_cpu) {
        std::sort(vec.begin(), vec.end(), [](auto &a, auto &b) { return a.second > b.second; });
        std::cerr << "CPU " << cpu << ":\n";
        const auto n = std::min<size_t>(top_n, vec.size());
        for (size_t i = 0; i < n; ++i) {
            std::cerr << "  " << vec[i].first << " -> " << vec[i].second << " " << time_unit
                      << "\n";
        }
    }
}
