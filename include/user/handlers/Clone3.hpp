#pragma once
#include "handlers/Base.hpp"
#include <string>

class Clone3Handler : public BaseHandler {

    CallBackContext<Clone3Handler> _rb_ctx{};

    static int sample_cb(void *ctx, void *data, size_t len);
    static constexpr char _obj_name[] = "clone3.o";

  protected:
    void onSample(const char *tag, const void *data, size_t len);

  public:
    explicit Clone3Handler(int poll_timeout_ms);
    ~Clone3Handler() override;

    void stop() override;
    bool install() override;
    void detach() override;
    void freezeProducer() override;
    uint64_t snapshotTotal() override;
    void onSample(void *data, size_t len) override;
};
