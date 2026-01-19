#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class PayMetricsController : public drogon::HttpController<PayMetricsController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(PayMetricsController::authMetrics,
                  "/pay/metrics/auth",
                  Get,
                  Options,
                  "PayAuthFilter");
    ADD_METHOD_TO(PayMetricsController::authMetricsProm,
                  "/pay/metrics/auth.prom",
                  Get,
                  Options,
                  "PayAuthFilter");
    METHOD_LIST_END

    void authMetrics(const HttpRequestPtr &req,
                     std::function<void(const HttpResponsePtr &)> &&callback);
    void authMetricsProm(const HttpRequestPtr &req,
                         std::function<void(const HttpResponsePtr &)> &&callback);
};
