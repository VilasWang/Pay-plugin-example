#include "PayAuthMetrics.h"

std::atomic<uint64_t> PayAuthMetrics::missingKey_{0};
std::atomic<uint64_t> PayAuthMetrics::invalidKey_{0};
std::atomic<uint64_t> PayAuthMetrics::scopeDenied_{0};
std::atomic<uint64_t> PayAuthMetrics::notConfigured_{0};

void PayAuthMetrics::incMissingKey()
{
    ++missingKey_;
}

void PayAuthMetrics::incInvalidKey()
{
    ++invalidKey_;
}

void PayAuthMetrics::incScopeDenied()
{
    ++scopeDenied_;
}

void PayAuthMetrics::incNotConfigured()
{
    ++notConfigured_;
}

Json::Value PayAuthMetrics::snapshot()
{
    Json::Value root;
    root["missing_key"] =
        static_cast<Json::UInt64>(missingKey_.load());
    root["invalid_key"] =
        static_cast<Json::UInt64>(invalidKey_.load());
    root["scope_denied"] =
        static_cast<Json::UInt64>(scopeDenied_.load());
    root["not_configured"] =
        static_cast<Json::UInt64>(notConfigured_.load());
    return root;
}
