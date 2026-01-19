#include "PayAuthFilter.h"
#include "PayAuthMetrics.h"
#include <drogon/drogon.h>
#include <algorithm>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

namespace
{
std::string trim(const std::string &value)
{
    const auto start = value.find_first_not_of(" \t");
    if (start == std::string::npos)
    {
        return {};
    }
    const auto end = value.find_last_not_of(" \t");
    return value.substr(start, end - start + 1);
}

std::vector<std::string> splitKeys(const std::string &value)
{
    std::vector<std::string> keys;
    std::stringstream ss(value);
    std::string token;
    while (std::getline(ss, token, ','))
    {
        auto key = trim(token);
        if (!key.empty())
        {
            keys.push_back(key);
        }
    }
    return keys;
}

std::string extractApiKey(const drogon::HttpRequestPtr &req)
{
    auto key = req->getHeader("X-Api-Key");
    if (!key.empty())
    {
        return key;
    }

    const auto auth = req->getHeader("Authorization");
    const std::string bearer = "Bearer ";
    if (auth.rfind(bearer, 0) == 0 && auth.size() > bearer.size())
    {
        return auth.substr(bearer.size());
    }
    return auth;
}

std::string resolveScope(const drogon::HttpRequestPtr &req)
{
    const auto &path = req->path();
    if (path.rfind("/pay/refund/query", 0) == 0)
    {
        return "refund_query";
    }
    if (path.rfind("/pay/refund", 0) == 0)
    {
        return "refund";
    }
    if (path.rfind("/pay/query", 0) == 0)
    {
        return "order_query";
    }
    return {};
}
}  // namespace

void PayAuthFilter::doFilter(const drogon::HttpRequestPtr &req,
                             drogon::FilterCallback &&fcb,
                             drogon::FilterChainCallback &&fccb)
{
    if (req->method() == drogon::Options)
    {
        fccb();
        return;
    }

    std::vector<std::string> allowedKeys;
    const auto &customConfig = drogon::app().getCustomConfig();
    if (customConfig.isMember("pay") &&
        customConfig["pay"].isMember("api_keys") &&
        customConfig["pay"]["api_keys"].isArray())
    {
        for (const auto &item : customConfig["pay"]["api_keys"])
        {
            auto key = item.asString();
            if (!key.empty())
            {
                allowedKeys.push_back(key);
            }
        }
    }

    if (const char *singleKey = std::getenv("PAY_API_KEY"))
    {
        auto key = trim(singleKey);
        if (!key.empty())
        {
            allowedKeys.push_back(key);
        }
    }

    if (const char *multiKeys = std::getenv("PAY_API_KEYS"))
    {
        const auto extra = splitKeys(multiKeys);
        allowedKeys.insert(allowedKeys.end(), extra.begin(), extra.end());
    }

    if (allowedKeys.empty())
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k503ServiceUnavailable);
        resp->setBody("api key not configured");
        LOG_WARN << "PayAuthFilter: api key not configured";
        PayAuthMetrics::incNotConfigured();
        fcb(resp);
        return;
    }

    const auto key = extractApiKey(req);
    if (key.empty())
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k401Unauthorized);
        resp->setBody("missing api key");
        LOG_WARN << "PayAuthFilter: missing api key";
        PayAuthMetrics::incMissingKey();
        fcb(resp);
        return;
    }

    const auto match =
        std::find(allowedKeys.begin(), allowedKeys.end(), key) !=
        allowedKeys.end();
    if (!match)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k401Unauthorized);
        resp->setBody("invalid api key");
        LOG_WARN << "PayAuthFilter: invalid api key";
        PayAuthMetrics::incInvalidKey();
        fcb(resp);
        return;
    }

    const auto scope = resolveScope(req);
    if (!scope.empty() && customConfig.isMember("pay") &&
        customConfig["pay"].isMember("api_key_scopes") &&
        customConfig["pay"]["api_key_scopes"].isObject())
    {
        const auto &scopeConfig = customConfig["pay"]["api_key_scopes"];
        if (scopeConfig.isMember(key))
        {
            const auto &scopes = scopeConfig[key];
            bool allowed = false;
            if (scopes.isArray())
            {
                for (const auto &item : scopes)
                {
                    if (item.asString() == scope)
                    {
                        allowed = true;
                        break;
                    }
                }
            }
            if (!allowed)
            {
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k403Forbidden);
                resp->setBody("api key scope not allowed");
                LOG_WARN << "PayAuthFilter: key scope not allowed";
                PayAuthMetrics::incScopeDenied();
                fcb(resp);
                return;
            }
        }
        else if (customConfig["pay"].isMember("api_key_default_scopes"))
        {
            const auto &defaults = customConfig["pay"]["api_key_default_scopes"];
            bool allowed = false;
            if (defaults.isArray())
            {
                for (const auto &item : defaults)
                {
                    if (item.asString() == scope)
                    {
                        allowed = true;
                        break;
                    }
                }
            }
            if (!allowed)
            {
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k403Forbidden);
                resp->setBody("api key scope not allowed");
                LOG_WARN << "PayAuthFilter: default scope not allowed";
                PayAuthMetrics::incScopeDenied();
                fcb(resp);
                return;
            }
        }
    }

    fccb();
}
