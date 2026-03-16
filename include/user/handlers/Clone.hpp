#pragma once
#include "handlers/Base.hpp"
#include <string>

class CloneHandler : public BaseHandler {

    static constexpr char _obj_name[] = "clone.o";

    CallBackContext<CloneHandler> _rb_ctx{};

    static int sample_cb(void *ctx, void *data, size_t len);

  protected:
    int onSample(const char *tag, void *data, size_t len);

  public:
    explicit CloneHandler(int poll_timeout_ms);
    ~CloneHandler() override;

    bool install() override;
    void detach() override;
    void stop() override;
    void freezeProducer() override;
    uint64_t snapshotTotal() override;
    void onSample(void *data, size_t len) override;
};
