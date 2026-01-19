#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class MetricsController : public drogon::HttpController<MetricsController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(MetricsController::metrics, "/metrics", Get, Options);
    METHOD_LIST_END

    void metrics(const HttpRequestPtr &req,
                 std::function<void(const HttpResponsePtr &)> &&callback);
};
