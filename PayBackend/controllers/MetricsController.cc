#include "MetricsController.h"
#include "../filters/PayAuthMetrics.h"
#include <drogon/HttpClient.h>

namespace
{
std::string buildAuthMetricsProm()
{
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

    return body;
}
}  // namespace

void MetricsController::metrics(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback)
{
    if (req->method() == Options)
    {
        auto resp = HttpResponse::newHttpResponse();
        callback(resp);
        return;
    }

    const auto &customConfig = drogon::app().getCustomConfig();
    std::string baseUrl = "http://127.0.0.1:5566/metrics/base";
    if (customConfig.isMember("pay") &&
        customConfig["pay"].isMember("metrics_base_url"))
    {
        baseUrl = customConfig["pay"]["metrics_base_url"].asString();
    }

    std::string clientHost = baseUrl;
    std::string basePath = "/";
    const auto schemePos = baseUrl.find("://");
    if (schemePos != std::string::npos)
    {
        const auto pathPos = baseUrl.find('/', schemePos + 3);
        if (pathPos != std::string::npos)
        {
            clientHost = baseUrl.substr(0, pathPos);
            basePath = baseUrl.substr(pathPos);
        }
    }

    auto client = drogon::HttpClient::newHttpClient(clientHost);
    auto request = drogon::HttpRequest::newHttpRequest();
    request->setMethod(drogon::Get);
    request->setPath(basePath);

    auto callbackPtr =
        std::make_shared<std::function<void(const HttpResponsePtr &)>>(
            std::move(callback));

    client->sendRequest(
        request,
        [callbackPtr](drogon::ReqResult result,
                      const drogon::HttpResponsePtr &resp) {
            std::string body = buildAuthMetricsProm();
            if (result == drogon::ReqResult::Ok && resp)
            {
                body = std::string(resp->body()) + "\n" + body;
            }
            else
            {
                body =
                    "# NOTE base metrics unavailable\n" + body;
            }

            auto out = drogon::HttpResponse::newHttpResponse();
            out->setStatusCode(drogon::k200OK);
            out->setContentTypeCode(drogon::CT_TEXT_PLAIN);
            out->setBody(body);
            (*callbackPtr)(out);
        });
}
