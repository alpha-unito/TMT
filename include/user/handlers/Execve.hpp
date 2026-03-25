#pragma once
#include "handlers/Base.hpp"
#include <string>

class ExecveHandler : public BaseHandler {

    static constexpr char _obj_name[] = "execve.o";
    CallBackContext<ExecveHandler> _rb_in_ctx{}, _rb_out_ctx{};

  public:
    ExecveHandler(int poll_timeout_ms = 100);
    ~ExecveHandler() override;

    bool install() override;
    void stop() override;
    void detach() override;
    void freezeProducer() override;
    uint64_t snapshotTotal() override;
    void onSample(void *data, size_t len) override;
    void onSample(const char *tag, const void *data, size_t len);
};
