#pragma once

#include <atomic>
#include <json/json.h>

class PayAuthMetrics
{
  public:
    static void incMissingKey();
    static void incInvalidKey();
    static void incScopeDenied();
    static void incNotConfigured();
    static Json::Value snapshot();

  private:
    static std::atomic<uint64_t> missingKey_;
    static std::atomic<uint64_t> invalidKey_;
    static std::atomic<uint64_t> scopeDenied_;
    static std::atomic<uint64_t> notConfigured_;
};
