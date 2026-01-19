#pragma once

#include <drogon/HttpFilter.h>

class PayAuthFilter : public drogon::HttpFilter<PayAuthFilter>
{
  public:
    void doFilter(const drogon::HttpRequestPtr &req,
                  drogon::FilterCallback &&fcb,
                  drogon::FilterChainCallback &&fccb) override;
};
