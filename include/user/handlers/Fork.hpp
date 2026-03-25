#pragma once
#include "handlers/Base.hpp"

class ForkHandler : public BaseHandler {

    CallBackContext<ForkHandler> _rb_fork_ctx{};
    static constexpr char _obj_name[] = "fork.o";

  public:
    explicit ForkHandler(int poll_timeout_ms = 100);
    ~ForkHandler() override;

    bool install() override;
    void detach() override;
    void stop() override;
    void freezeProducer() override;
    uint64_t snapshotTotal() override;
    void onSample(void *data, size_t len) override;
    void onSample(const char *tag, void *data, size_t len);
};
