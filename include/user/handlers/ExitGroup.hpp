#pragma once
#include "handlers/Base.hpp"
#include <string>

class ExitGroupHandler : public BaseHandler {
    static constexpr char _obj_name[] = "exit_group.o";

  public:
    explicit ExitGroupHandler(int poll_timeout_ms = 100);
    ~ExitGroupHandler() override;

    bool install() override;
    void stop() override;
    void detach() override;
    void freezeProducer() override;
    uint64_t snapshotTotal() override;
    void onSample(void *data, size_t len) override;
};
