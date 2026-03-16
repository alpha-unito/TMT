#pragma once
#include "handlers/Base.hpp"

class  SwitchHandler : public BaseHandler {

    uint32_t _shell_pid_hint, _cmd_pid_hint;
    static constexpr char _obj_name[] = "sched_switch.o";

  public:
    explicit SwitchHandler(int poll_timeout_ms = 100);
    ~SwitchHandler() override;

    bool install() override;
    void detach() override;
    void stop() override;
    void freezeProducer() override;
    uint64_t snapshotTotal() override;
    void onSample(void *data, size_t len) override;
    void setRootPid(uint32_t shell_pid, uint32_t cmd_pid);
};
