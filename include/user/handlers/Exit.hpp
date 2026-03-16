#pragma once
#include "handlers/Base.hpp"
#include <string>

class ExitHandler : public BaseHandler {

    CallBackContext<ExitHandler> _rb_exit_ctx{}, _rb_exitgrp_ctx{};

    static constexpr char _obj_name[] = "exit.o";

  public:
    explicit ExitHandler(int poll_timeout_ms = 100);
    ~ExitHandler() override;

    void stop() override;
    bool install() override;
    void detach() override;
    void freezeProducer() override;
    uint64_t snapshotTotal() override;
    void onSample(void *data, size_t len) override;
    void onSample(const char *tag, void *data, size_t len);
};
