#pragma once

#include <drogon/plugins/Plugin.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/nosql/RedisClient.h>
#include <drogon/orm/DbClient.h>
#include <json/json.h>
#include <memory>
#include <string>
#include <trantor/net/EventLoop.h>
#include <trantor/utils/Date.h>
#include "WechatPayClient.h"

class PayPlugin : public drogon::Plugin<PayPlugin>
{
  public:
    PayPlugin() = default;
    void initAndStart(const Json::Value &config) override;
    void shutdown() override;

    void createPayment(
        const drogon::HttpRequestPtr &req,
        std::function<void(const drogon::HttpResponsePtr &)> &&callback);

    void queryOrder(
        const drogon::HttpRequestPtr &req,
        std::function<void(const drogon::HttpResponsePtr &)> &&callback);

    void refund(
        const drogon::HttpRequestPtr &req,
        std::function<void(const drogon::HttpResponsePtr &)> &&callback);

    void queryRefund(
        const drogon::HttpRequestPtr &req,
        std::function<void(const drogon::HttpResponsePtr &)> &&callback);

    void reconcileSummary(
        const drogon::HttpRequestPtr &req,
        std::function<void(const drogon::HttpResponsePtr &)> &&callback);

    void handleWechatCallback(
        const drogon::HttpRequestPtr &req,
        std::function<void(const drogon::HttpResponsePtr &)> &&callback);

    void setTestClients(
        const std::shared_ptr<WechatPayClient> &wechatClient,
        const std::shared_ptr<drogon::orm::DbClient> &dbClient,
        const drogon::nosql::RedisClientPtr &redisClient = nullptr,
        bool useRedisIdempotency = false);

  private:
    void startReconcileTimer();
    void syncOrderStatusFromWechat(
        const std::string &orderNo,
        const Json::Value &result,
        std::function<void(const std::string &orderStatus)> &&done);
    void syncRefundStatusFromWechat(
        const std::string &refundNo,
        const Json::Value &result,
        std::function<void(const std::string &refundStatus)> &&done);
    void proceedCreatePayment(
        const std::shared_ptr<std::function<void(const drogon::HttpResponsePtr &)>> &callbackPtr,
        const std::string &orderNo,
        const std::string &paymentNo,
        const std::string &amount,
        const std::string &currency,
        const std::string &title,
        const std::string &notifyUrlOverride,
        const std::string &attach,
        const Json::Value &sceneInfo,
        bool hasSceneInfo,
        const std::shared_ptr<trantor::Date> &expireAt,
        int64_t totalFen,
        int64_t userIdValue,
        const std::string &idempotencyKey,
        const std::string &requestHash);
    void proceedRefund(
        const std::shared_ptr<std::function<void(const drogon::HttpResponsePtr &)>> &callbackPtr,
        const std::string &refundNo,
        const std::string &orderNo,
        const std::string &paymentNo,
        const std::string &amount,
        const std::string &idempotencyKey,
        const std::string &requestHash);

    Json::Value pluginConfig_;
    std::shared_ptr<WechatPayClient> wechatClient_;
    std::shared_ptr<drogon::orm::DbClient> dbClient_;
    drogon::nosql::RedisClientPtr redisClient_;
    bool useRedisIdempotency_{false};
    int64_t idempotencyTtlSeconds_{604800};
    bool reconcileEnabled_{true};
    int reconcileIntervalSeconds_{300};
    int reconcileBatchSize_{50};
    trantor::TimerId reconcileTimerId_;
};
