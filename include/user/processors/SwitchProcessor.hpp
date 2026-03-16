#pragma once
#include "common.hpp"
#include <string>
#include <vector>

class SwitchProcessor {
    std::vector<Event> _events;
    std::vector<Slice> _slices;

  public:
    explicit SwitchProcessor(const std::vector<Event> &events);

    void buildSlices(bool debug = false);
    void storeCsv(const std::string &filename = "out/oncpu_slices.csv") const;
    void plotTopRuntimePerCPU(int top_n = 10, const std::string &time_unit = "ms") const;
};
