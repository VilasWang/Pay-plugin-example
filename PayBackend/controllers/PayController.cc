#include "PayController.h"

void PayController::createPayment(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback)
{
    if (req->method() == Options)
    {
        auto resp = HttpResponse::newHttpResponse();
        callback(resp);
        return;
    }

    auto plugin = drogon::app().getPlugin<PayPlugin>();
    plugin->createPayment(req, std::move(callback));
}

void PayController::queryOrder(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback)
{
    if (req->method() == Options)
    {
        auto resp = HttpResponse::newHttpResponse();
        callback(resp);
        return;
    }

    auto plugin = drogon::app().getPlugin<PayPlugin>();
    plugin->queryOrder(req, std::move(callback));
}

void PayController::refund(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback)
{
    if (req->method() == Options)
    {
        auto resp = HttpResponse::newHttpResponse();
        callback(resp);
        return;
    }

    auto plugin = drogon::app().getPlugin<PayPlugin>();
    plugin->refund(req, std::move(callback));
}

void PayController::queryRefund(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback)
{
    if (req->method() == Options)
    {
        auto resp = HttpResponse::newHttpResponse();
        callback(resp);
        return;
    }

    auto plugin = drogon::app().getPlugin<PayPlugin>();
    plugin->queryRefund(req, std::move(callback));
}

void PayController::reconcileSummary(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback)
{
    if (req->method() == Options)
    {
        auto resp = HttpResponse::newHttpResponse();
        callback(resp);
        return;
    }

    auto plugin = drogon::app().getPlugin<PayPlugin>();
    plugin->reconcileSummary(req, std::move(callback));
}
