#include "PayMetricsController.h"
#include "../filters/PayAuthMetrics.h"

void PayMetricsController::authMetrics(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback)
{
    if (req->method() == Options)
    {
        auto resp = HttpResponse::newHttpResponse();
        callback(resp);
        return;
    }

    auto body = PayAuthMetrics::snapshot();
    auto resp = HttpResponse::newHttpJsonResponse(body);
    callback(resp);
}

void PayMetricsController::authMetricsProm(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback)
{
    if (req->method() == Options)
    {
        auto resp = HttpResponse::newHttpResponse();
        callback(resp);
        return;
    }

    const auto snapshot = PayAuthMetrics::snapshot();

    std::string body;
    body += "# HELP pay_auth_missing_key_total Missing API key count\n";
    body += "# TYPE pay_auth_missing_key_total counter\n";
    body += "pay_auth_missing_key_total " +
            std::to_string(snapshot["missing_key"].asUInt64()) + "\n";

    body += "# HELP pay_auth_invalid_key_total Invalid API key count\n";
    body += "# TYPE pay_auth_invalid_key_total counter\n";
    body += "pay_auth_invalid_key_total " +
            std::to_string(snapshot["invalid_key"].asUInt64()) + "\n";

    body += "# HELP pay_auth_scope_denied_total Scope denied count\n";
    body += "# TYPE pay_auth_scope_denied_total counter\n";
    body += "pay_auth_scope_denied_total " +
            std::to_string(snapshot["scope_denied"].asUInt64()) + "\n";

    body += "# HELP pay_auth_not_configured_total Not configured count\n";
    body += "# TYPE pay_auth_not_configured_total counter\n";
    body += "pay_auth_not_configured_total " +
            std::to_string(snapshot["not_configured"].asUInt64()) + "\n";

    auto resp = HttpResponse::newHttpResponse();
    resp->setStatusCode(k200OK);
    resp->setContentTypeCode(CT_TEXT_PLAIN);
    resp->setBody(body);
    callback(resp);
}
