#pragma once

#include <drogon/HttpController.h>
#include "../plugins/PayPlugin.h"

using namespace drogon;

class PayController : public drogon::HttpController<PayController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(PayController::createPayment, "/pay/create", Post, Options);
    ADD_METHOD_TO(PayController::queryOrder,
                  "/pay/query",
                  Get,
                  Options,
                  "PayAuthFilter");
    ADD_METHOD_TO(PayController::refund,
                  "/pay/refund",
                  Post,
                  Options,
                  "PayAuthFilter");
    ADD_METHOD_TO(PayController::queryRefund,
                  "/pay/refund/query",
                  Get,
                  Options,
                  "PayAuthFilter");
    METHOD_LIST_END

    void createPayment(const HttpRequestPtr &req,
                       std::function<void(const HttpResponsePtr &)> &&callback);

    void queryOrder(const HttpRequestPtr &req,
                    std::function<void(const HttpResponsePtr &)> &&callback);

    void refund(const HttpRequestPtr &req,
                std::function<void(const HttpResponsePtr &)> &&callback);

    void queryRefund(const HttpRequestPtr &req,
                     std::function<void(const HttpResponsePtr &)> &&callback);
};
