#include <drogon/drogon_test.h>
#include "../filters/PayAuthFilter.h"
#include "../filters/PayAuthMetrics.h"
#include <cstdlib>

namespace
{
void setEnvVar(const char *key, const char *value)
{
#ifdef _WIN32
    _putenv_s(key, value ? value : "");
#else
    if (value && *value)
    {
        setenv(key, value, 1);
    }
    else
    {
        unsetenv(key);
    }
#endif
}

Json::UInt64 metricValue(const Json::Value &snapshot, const char *key)
{
    return snapshot.get(key, 0).asUInt64();
}
}  // namespace

DROGON_TEST(PayAuthFilter_NotConfigured)
{
    setEnvVar("PAY_API_KEY", "");
    setEnvVar("PAY_API_KEYS", "");

    PayAuthFilter filter;
    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setPath("/pay/query");

    drogon::HttpResponsePtr resp;
    bool fcbCalled = false;
    bool fccbCalled = false;
    const auto before = PayAuthMetrics::snapshot();

    filter.doFilter(
        req,
        [&](const drogon::HttpResponsePtr &r) {
            resp = r;
            fcbCalled = true;
        },
        [&]() { fccbCalled = true; });

    CHECK(fcbCalled);
    CHECK(!fccbCalled);
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k503ServiceUnavailable);
    CHECK(resp->body() == "api key not configured");

    const auto after = PayAuthMetrics::snapshot();
    CHECK(metricValue(after, "not_configured") ==
          metricValue(before, "not_configured") + 1);
}

DROGON_TEST(PayAuthFilter_MissingKey)
{
    setEnvVar("PAY_API_KEY", "secret");
    setEnvVar("PAY_API_KEYS", "");

    PayAuthFilter filter;
    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setPath("/pay/query");

    drogon::HttpResponsePtr resp;
    bool fcbCalled = false;
    bool fccbCalled = false;
    const auto before = PayAuthMetrics::snapshot();

    filter.doFilter(
        req,
        [&](const drogon::HttpResponsePtr &r) {
            resp = r;
            fcbCalled = true;
        },
        [&]() { fccbCalled = true; });

    CHECK(fcbCalled);
    CHECK(!fccbCalled);
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k401Unauthorized);
    CHECK(resp->body() == "missing api key");

    const auto after = PayAuthMetrics::snapshot();
    CHECK(metricValue(after, "missing_key") ==
          metricValue(before, "missing_key") + 1);
}

DROGON_TEST(PayAuthFilter_InvalidKey)
{
    setEnvVar("PAY_API_KEY", "secret");
    setEnvVar("PAY_API_KEYS", "");

    PayAuthFilter filter;
    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setPath("/pay/query");
    req->addHeader("X-Api-Key", "wrong");

    drogon::HttpResponsePtr resp;
    bool fcbCalled = false;
    bool fccbCalled = false;
    const auto before = PayAuthMetrics::snapshot();

    filter.doFilter(
        req,
        [&](const drogon::HttpResponsePtr &r) {
            resp = r;
            fcbCalled = true;
        },
        [&]() { fccbCalled = true; });

    CHECK(fcbCalled);
    CHECK(!fccbCalled);
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k401Unauthorized);
    CHECK(resp->body() == "invalid api key");

    const auto after = PayAuthMetrics::snapshot();
    CHECK(metricValue(after, "invalid_key") ==
          metricValue(before, "invalid_key") + 1);
}

DROGON_TEST(PayAuthFilter_ValidKey)
{
    setEnvVar("PAY_API_KEY", "secret");
    setEnvVar("PAY_API_KEYS", "");

    PayAuthFilter filter;
    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setPath("/pay/query");
    req->addHeader("X-Api-Key", "secret");

    bool fcbCalled = false;
    bool fccbCalled = false;

    filter.doFilter(
        req,
        [&](const drogon::HttpResponsePtr &) { fcbCalled = true; },
        [&]() { fccbCalled = true; });

    CHECK(!fcbCalled);
    CHECK(fccbCalled);
}
