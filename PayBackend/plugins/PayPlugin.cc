#include "PayPlugin.h"
#include "../models/PayCallback.h"
#include "../models/PayIdempotency.h"
#include "../models/PayLedger.h"
#include "../models/PayOrder.h"
#include "../models/PayPayment.h"
#include "../models/PayRefund.h"
#include "../utils/PayUtils.h"
#include <drogon/drogon.h>
#include <drogon/orm/Criteria.h>
#include <drogon/orm/Mapper.h>
#include <drogon/utils/Utilities.h>
#include <atomic>
#include <memory>
#include <trantor/utils/Date.h>

namespace
{
using PayOrderModel = drogon_model::pay_test::PayOrder;
using PayPaymentModel = drogon_model::pay_test::PayPayment;
using PayRefundModel = drogon_model::pay_test::PayRefund;
using PayCallbackModel = drogon_model::pay_test::PayCallback;
using PayIdempotencyModel = drogon_model::pay_test::PayIdempotency;
using PayLedgerModel = drogon_model::pay_test::PayLedger;
using pay::utils::getRequiredString;
using pay::utils::parseAmountToFen;
using pay::utils::toJsonString;
using pay::utils::mapTradeState;
using pay::utils::mapRefundStatus;

void insertLedgerEntry(
    const std::shared_ptr<drogon::orm::DbClient> &dbClient,
    int64_t userId,
    const std::string &orderNo,
    const std::string &paymentNo,
    const std::string &entryType,
    const std::string &amount)
{
    if (!dbClient)
    {
        return;
    }

    PayLedgerModel ledger;
    ledger.setUserId(userId);
    ledger.setOrderNo(orderNo);
    if (paymentNo.empty())
    {
        ledger.setPaymentNoToNull();
    }
    else
    {
        ledger.setPaymentNo(paymentNo);
    }
    ledger.setEntryType(entryType);
    ledger.setAmount(amount);
    ledger.setCreatedAt(trantor::Date::now());

    drogon::orm::Mapper<PayLedgerModel> ledgerMapper(dbClient);
    ledgerMapper.insert(
        ledger,
        [](const PayLedgerModel &) {},
        [](const drogon::orm::DrogonDbException &e) {
            LOG_ERROR << "Ledger insert error: " << e.base().what();
        });
}

void storeIdempotencySnapshot(
    const std::shared_ptr<drogon::orm::DbClient> &dbClient,
    const std::string &idempotencyKey,
    const std::string &requestHash,
    const std::string &responseSnapshot,
    int64_t ttlSeconds)
{
    if (!dbClient || idempotencyKey.empty())
    {
        return;
    }

    PayIdempotencyModel idemp;
    idemp.setIdempotencyKey(idempotencyKey);
    idemp.setRequestHash(requestHash);
    idemp.setResponseSnapshot(responseSnapshot);
    const auto now = trantor::Date::now();
    const auto expiresAt = trantor::Date(
        now.microSecondsSinceEpoch() +
        ttlSeconds * static_cast<int64_t>(1000000));
    idemp.setExpiresAt(expiresAt);

    drogon::orm::Mapper<PayIdempotencyModel> idempMapper(dbClient);
    idempMapper.insert(
        idemp,
        [](const PayIdempotencyModel &) {},
        [](const drogon::orm::DrogonDbException &e) {
            LOG_ERROR << "Idempotency insert error: " << e.base().what();
        });
}

std::string resolveIdempotencyKey(const drogon::HttpRequestPtr &req)
{
    auto key = req->getHeader("Idempotency-Key");
    if (key.empty())
    {
        key = req->getHeader("X-Idempotency-Key");
    }
    return key;
}


}  // namespace

void PayPlugin::initAndStart(const Json::Value &config)
{
    pluginConfig_ = config;
    if (config.isMember("wechat_pay"))
    {
        wechatClient_ = std::make_shared<WechatPayClient>(config["wechat_pay"]);
    }
    if (config.isMember("postgres"))
    {
        auto dbClientName =
            config["postgres"].get("db_client_name", "default").asString();
        try
        {
            dbClient_ = drogon::app().getDbClient(dbClientName);
        }
        catch (...)
        {
            LOG_ERROR << "Failed to get DB Client: " << dbClientName;
        }
    }
    if (config.isMember("redis"))
    {
        auto redisClientName =
            config["redis"].get("client_name", "default").asString();
        try
        {
            redisClient_ = drogon::app().getRedisClient(redisClientName);
            if (redisClient_)
            {
                redisClient_->setTimeout(3.0);
            }
        }
        catch (...)
        {
            LOG_ERROR << "Failed to get Redis Client: " << redisClientName;
        }
    }
    useRedisIdempotency_ =
        config.get("use_redis_idempotency", false).asBool();
    idempotencyTtlSeconds_ =
        config.get("idempotency_ttl_seconds", 604800).asInt64();
    reconcileEnabled_ = config.get("reconcile_enabled", true).asBool();
    reconcileIntervalSeconds_ =
        config.get("reconcile_interval_seconds", 300).asInt();
    reconcileBatchSize_ = config.get("reconcile_batch_size", 50).asInt();

    startReconcileTimer();
}

void PayPlugin::shutdown()
{
    wechatClient_.reset();
    dbClient_.reset();
    redisClient_.reset();
    auto loop = drogon::app().getLoop();
    if (loop)
    {
        loop->invalidateTimer(reconcileTimerId_);
    }
}

void PayPlugin::setTestClients(
    const std::shared_ptr<WechatPayClient> &wechatClient,
    const std::shared_ptr<drogon::orm::DbClient> &dbClient,
    const drogon::nosql::RedisClientPtr &redisClient,
    bool useRedisIdempotency)
{
    wechatClient_ = wechatClient;
    dbClient_ = dbClient;
    redisClient_ = redisClient;
    useRedisIdempotency_ = useRedisIdempotency;
}

void PayPlugin::startReconcileTimer()
{
    if (!reconcileEnabled_)
    {
        return;
    }
    auto loop = drogon::app().getLoop();
    if (!loop)
    {
        return;
    }
    reconcileTimerId_ = loop->runEvery(
        reconcileIntervalSeconds_,
        [this]() {
            if (!dbClient_ || !wechatClient_)
            {
                return;
            }
            dbClient_->execSqlAsync(
                "SELECT order_no FROM pay_order WHERE status = $1 "
                "ORDER BY updated_at DESC LIMIT $2",
                [this](const drogon::orm::Result &r) {
                    for (const auto &row : r)
                    {
                        const std::string orderNo =
                            row["order_no"].as<std::string>();
                        wechatClient_->queryTransaction(
                            orderNo,
                            [this, orderNo](const Json::Value &result,
                                            const std::string &error) {
                                if (!error.empty())
                                {
                                    LOG_WARN
                                        << "Wechat query failed for order "
                                        << orderNo << ": " << error;
                                    return;
                                }
                                syncOrderStatusFromWechat(
                                    orderNo,
                                    result,
                                    [](const std::string &) {});
                            });
                    }
                },
                [](const drogon::orm::DrogonDbException &e) {
                    LOG_ERROR << "Reconcile query error: "
                              << e.base().what();
                },
                "PAYING",
                reconcileBatchSize_);

            dbClient_->execSqlAsync(
                "SELECT refund_no FROM pay_refund WHERE status IN ($1, $2) "
                "ORDER BY updated_at DESC LIMIT $3",
                [this](const drogon::orm::Result &r) {
                    for (const auto &row : r)
                    {
                        const std::string refundNo =
                            row["refund_no"].as<std::string>();
                        wechatClient_->queryRefund(
                            refundNo,
                            [this, refundNo](const Json::Value &result,
                                             const std::string &error) {
                                if (!error.empty())
                                {
                                    LOG_WARN
                                        << "Wechat refund query failed for "
                                        << refundNo << ": " << error;
                                    return;
                                }
                                syncRefundStatusFromWechat(
                                    refundNo,
                                    result,
                                    [](const std::string &) {});
                            });
                    }
                },
                [](const drogon::orm::DrogonDbException &e) {
                    LOG_ERROR << "Reconcile refund query error: "
                              << e.base().what();
                },
                "REFUND_INIT",
                "REFUNDING",
                reconcileBatchSize_);
        });
}

void PayPlugin::syncOrderStatusFromWechat(
    const std::string &orderNo,
    const Json::Value &result,
    std::function<void(const std::string &orderStatus)> &&done)
{
    const std::string tradeState = result.get("trade_state", "").asString();
    if (tradeState.empty())
    {
        if (done)
        {
            done("");
        }
        return;
    }

    std::string orderStatus;
    std::string paymentStatus;
    mapTradeState(tradeState, orderStatus, paymentStatus);
    const std::string transactionId =
        result.get("transaction_id", "").asString();
    const std::string responsePayload = toJsonString(result);

    if (!dbClient_)
    {
        if (done)
        {
            done(orderStatus);
        }
        return;
    }

    LOG_INFO << "Sync order status from WeChat: order_no=" << orderNo
             << " trade_state=" << tradeState
             << " order_status=" << orderStatus
             << " payment_status=" << paymentStatus;

    drogon::orm::Mapper<PayPaymentModel> paymentMapper(dbClient_);
    auto paymentCriteria =
        drogon::orm::Criteria(PayPaymentModel::Cols::_order_no,
                              drogon::orm::CompareOperator::EQ,
                              orderNo);
    paymentMapper.orderBy(PayPaymentModel::Cols::_created_at,
                          drogon::orm::SortOrder::DESC)
        .limit(1)
        .findBy(
            paymentCriteria,
            [this,
             orderNo,
             orderStatus,
             paymentStatus,
             transactionId,
             responsePayload,
             done](const std::vector<PayPaymentModel> &rows) {
                if (rows.empty())
                {
                    if (done)
                    {
                        done(orderStatus);
                    }
                    return;
                }
                auto payment = rows.front();
                const auto paymentNo = payment.getValueOfPaymentNo();
                if (payment.getValueOfStatus() == "SUCCESS")
                {
                    if (done)
                    {
                        done(orderStatus);
                    }
                    return;
                }
                payment.setStatus(paymentStatus);
                payment.setChannelTradeNo(transactionId);
                payment.setResponsePayload(responsePayload);
                payment.setUpdatedAt(trantor::Date::now());

                drogon::orm::Mapper<PayPaymentModel> paymentUpdater(dbClient_);
                paymentUpdater.update(
                    payment,
                    [this, orderNo, orderStatus, done](const size_t) {
                        drogon::orm::Mapper<PayOrderModel> orderMapper(
                            dbClient_);
                        auto orderCriteria =
                            drogon::orm::Criteria(
                                PayOrderModel::Cols::_order_no,
                                drogon::orm::CompareOperator::EQ,
                                orderNo);
                        orderMapper.findOne(
                            orderCriteria,
                            [this, orderStatus, done](PayOrderModel order) {
                                if (order.getValueOfStatus() == "PAID")
                                {
                                    if (done)
                                    {
                                        done(orderStatus);
                                    }
                                    return;
                                }
                                order.setStatus(orderStatus);
                                order.setUpdatedAt(trantor::Date::now());
                                drogon::orm::Mapper<PayOrderModel>
                                    orderUpdater(dbClient_);
                                orderUpdater.update(
                                    order,
                                    [done, orderStatus](const size_t) {
                                        if (done)
                                        {
                                            done(orderStatus);
                                        }
                                    },
                                    [](const drogon::orm::DrogonDbException &e) {
                                        LOG_ERROR
                                            << "Reconcile order update error: "
                                            << e.base().what();
                                    });
                            },
                            [](const drogon::orm::DrogonDbException &e) {
                                LOG_ERROR
                                    << "Reconcile order select error: "
                                    << e.base().what();
                            });
                    },
                    [](const drogon::orm::DrogonDbException &e) {
                        LOG_ERROR << "Reconcile payment update error: "
                                  << e.base().what();
                    });
            },
            [](const drogon::orm::DrogonDbException &e) {
                LOG_ERROR << "Reconcile payment select error: "
                          << e.base().what();
            });
}

void PayPlugin::syncRefundStatusFromWechat(
    const std::string &refundNo,
    const Json::Value &result,
    std::function<void(const std::string &refundStatus)> &&done)
{
    const std::string wechatStatus = result.get("status", "").asString();
    if (wechatStatus.empty())
    {
        if (done)
        {
            done("");
        }
        return;
    }

    const std::string refundStatus = mapRefundStatus(wechatStatus);
    const std::string refundId = result.get("refund_id", "").asString();

    LOG_INFO << "Sync refund status from WeChat: refund_no=" << refundNo
             << " wechat_status=" << wechatStatus
             << " refund_status=" << refundStatus;

    if (refundStatus.empty())
    {
        LOG_WARN << "Unknown refund status from WeChat: " << wechatStatus;
        if (done)
        {
            done("");
        }
        return;
    }

    if (!dbClient_)
    {
        if (done)
        {
            done(refundStatus);
        }
        return;
    }

    drogon::orm::Mapper<PayRefundModel> refundMapper(dbClient_);
    auto criteria = drogon::orm::Criteria(PayRefundModel::Cols::_refund_no,
                                          drogon::orm::CompareOperator::EQ,
                                          refundNo);
    refundMapper.findOne(
        criteria,
        [this, refundStatus, refundId, done](
            PayRefundModel refund) {
            if (refund.getValueOfStatus() == "REFUND_SUCCESS")
            {
                if (done)
                {
                    done(refundStatus);
                }
                return;
            }
            const auto orderNo = refund.getValueOfOrderNo();
            const auto paymentNo = refund.getValueOfPaymentNo();
            const auto refundAmount = refund.getValueOfAmount();
            refund.setStatus(refundStatus);
            refund.setChannelRefundNo(refundId);
            refund.setUpdatedAt(trantor::Date::now());

            drogon::orm::Mapper<PayRefundModel> refundUpdater(dbClient_);
            refundUpdater.update(
                refund,
                [this,
                 done,
                 refundStatus,
                 orderNo,
                 paymentNo,
                 refundAmount](const size_t) {
                    if (done)
                    {
                        done(refundStatus);
                    }
                    if (refundStatus == "REFUND_SUCCESS")
                    {
                        drogon::orm::Mapper<PayOrderModel> orderMapper(
                            dbClient_);
                        auto orderCriteria =
                            drogon::orm::Criteria(
                                PayOrderModel::Cols::_order_no,
                                drogon::orm::CompareOperator::EQ,
                                orderNo);
                        orderMapper.findOne(
                            orderCriteria,
                            [this, orderNo, paymentNo, refundAmount](
                                const PayOrderModel &order) {
                                insertLedgerEntry(
                                    dbClient_,
                                    order.getValueOfUserId(),
                                    orderNo,
                                    paymentNo,
                                    "REFUND",
                                    refundAmount);
                            },
                            [](const drogon::orm::DrogonDbException &e) {
                                LOG_ERROR
                                    << "Refund ledger order lookup error: "
                                    << e.base().what();
                            });
                    }
                },
                [](const drogon::orm::DrogonDbException &e) {
                    LOG_ERROR << "Reconcile refund update error: "
                              << e.base().what();
                });
        },
        [](const drogon::orm::DrogonDbException &e) {
            LOG_ERROR << "Reconcile refund select error: "
                      << e.base().what();
        });
}

void PayPlugin::proceedCreatePayment(
    const std::shared_ptr<std::function<void(const drogon::HttpResponsePtr &)>> &callbackPtr,
    const std::string &orderNo,
    const std::string &paymentNo,
    const std::string &amount,
    const std::string &currency,
    const std::string &title,
    int64_t totalFen,
    int64_t userIdValue,
    const std::string &idempotencyKey,
    const std::string &requestHash)
{
    drogon::orm::Mapper<PayOrderModel> orderMapper(dbClient_);
    PayOrderModel order;
    order.setOrderNo(orderNo);
    order.setUserId(userIdValue);
    order.setAmount(amount);
    order.setCurrency(currency);
    order.setStatus("CREATED");
    order.setChannel("wechat");
    order.setTitle(title);
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());

    Json::Value payload;
    payload["description"] = title;
    payload["out_trade_no"] = orderNo;
    payload["amount"]["total"] = static_cast<Json::Int64>(totalFen);
    payload["amount"]["currency"] = currency;
    const std::string requestPayload = toJsonString(payload);

    orderMapper.insert(
        order,
        [this,
         callbackPtr,
         orderNo,
         paymentNo,
         amount,
         payload,
         requestPayload,
         idempotencyKey,
         requestHash](const PayOrderModel &) {
            drogon::orm::Mapper<PayPaymentModel> paymentMapper(dbClient_);
            PayPaymentModel payment;
            payment.setOrderNo(orderNo);
            payment.setPaymentNo(paymentNo);
            payment.setStatus("INIT");
            payment.setAmount(amount);
            payment.setRequestPayload(requestPayload);
            payment.setCreatedAt(trantor::Date::now());
            payment.setUpdatedAt(trantor::Date::now());

            paymentMapper.insert(
                payment,
                [this,
                 callbackPtr,
                 orderNo,
                 paymentNo,
                 payload,
                 idempotencyKey,
                 requestHash](const PayPaymentModel &) {
                    wechatClient_->createTransactionNative(
                        payload,
                        [this,
                         callbackPtr,
                         orderNo,
                         paymentNo,
                         idempotencyKey,
                         requestHash](
                            const Json::Value &result,
                            const std::string &error) {
                            if (!error.empty())
                            {
                                Json::Value errJson;
                                errJson["error"] = error;
                                const std::string errPayload =
                                    toJsonString(errJson);
                                auto resp =
                                    drogon::HttpResponse::newHttpResponse();
                                resp->setStatusCode(
                                    drogon::k502BadGateway);
                                resp->setBody("wechat error: " + error);
                                drogon::orm::Mapper<PayPaymentModel>
                                    paymentMapper(dbClient_);
                                auto payCriteria = drogon::orm::Criteria(
                                    PayPaymentModel::Cols::_payment_no,
                                    drogon::orm::CompareOperator::EQ,
                                    paymentNo);
                                paymentMapper.findOne(
                                    payCriteria,
                                    [this, errPayload, orderNo](PayPaymentModel payment) {
                                        payment.setStatus("FAIL");
                                        payment.setResponsePayload(errPayload);
                                        payment.setUpdatedAt(
                                            trantor::Date::now());
                                        drogon::orm::Mapper<PayPaymentModel>
                                            paymentUpdater(dbClient_);
                                        paymentUpdater.update(
                                            payment,
                                            [this, orderNo](const size_t) {
                                                drogon::orm::Mapper<PayOrderModel>
                                                    orderMapper(dbClient_);
                                                auto orderCriteria =
                                                    drogon::orm::Criteria(
                                                        PayOrderModel::Cols::
                                                            _order_no,
                                                        drogon::orm::
                                                            CompareOperator::EQ,
                                                        orderNo);
                                                orderMapper.findOne(
                                                    orderCriteria,
                                                    [this](PayOrderModel order) {
                                                        order.setStatus(
                                                            "FAILED");
                                                        order.setUpdatedAt(
                                                            trantor::Date::now());
                                                        drogon::orm::Mapper<
                                                            PayOrderModel>
                                                            orderUpdater(
                                                                dbClient_);
                                                        orderUpdater.update(
                                                            order,
                                                            [](const size_t) {},
                                                            [](const drogon::orm::DrogonDbException &) {});
                                                    },
                                                    [](const drogon::orm::DrogonDbException &) {});
                                            },
                                            [](const drogon::orm::DrogonDbException &) {});
                                    },
                                    [](const drogon::orm::DrogonDbException &) {});
                                (*callbackPtr)(resp);
                                return;
                            }

                            const std::string responsePayload =
                                toJsonString(result);

                            drogon::orm::Mapper<PayPaymentModel> paymentMapper(
                                dbClient_);
                            auto payCriteria = drogon::orm::Criteria(
                                PayPaymentModel::Cols::_payment_no,
                                drogon::orm::CompareOperator::EQ,
                                paymentNo);
                            paymentMapper.findOne(
                                payCriteria,
                                [this,
                                 callbackPtr,
                                 orderNo,
                                 paymentNo,
                                 result,
                                 responsePayload,
                                 idempotencyKey,
                                 requestHash](PayPaymentModel payment) {
                                    payment.setStatus("PROCESSING");
                                    payment.setResponsePayload(
                                        responsePayload);
                                    payment.setUpdatedAt(
                                        trantor::Date::now());
                                    drogon::orm::Mapper<PayPaymentModel>
                                        paymentUpdater(dbClient_);
                                    paymentUpdater.update(
                                        payment,
                                        [this,
                                         callbackPtr,
                                         orderNo,
                                         paymentNo,
                                         result,
                                         idempotencyKey,
                                         requestHash](const size_t) {
                                            drogon::orm::Mapper<PayOrderModel>
                                                orderMapper(dbClient_);
                                            auto orderCriteria =
                                                drogon::orm::Criteria(
                                                    PayOrderModel::Cols::
                                                        _order_no,
                                                    drogon::orm::
                                                        CompareOperator::EQ,
                                                    orderNo);
                                            orderMapper.findOne(
                                                orderCriteria,
                                                [this,
                                                 callbackPtr,
                                                 orderNo,
                                                 paymentNo,
                                                 result,
                                                 idempotencyKey,
                                                 requestHash](
                                                    PayOrderModel order) {
                                                    order.setStatus("PAYING");
                                                    order.setUpdatedAt(
                                                        trantor::Date::now());
                                                    drogon::orm::Mapper<
                                                        PayOrderModel>
                                                        orderUpdater(
                                                            dbClient_);
                                                    orderUpdater.update(
                                                        order,
                                                        [this,
                                                         callbackPtr,
                                                         orderNo,
                                                         paymentNo,
                                                         result,
                                                         idempotencyKey,
                                                         requestHash](
                                                            const size_t) {
                                                            Json::Value body;
                                                            body["order_no"] =
                                                                orderNo;
                                                            body["payment_no"] =
                                                                paymentNo;
                                                            body["status"] =
                                                                "PAYING";
                                                            body["wechat_response"] =
                                                                result;
                                                            const auto codeUrl =
                                                                result.get(
                                                                    "code_url",
                                                                    "")
                                                                    .asString();
                                                            if (!codeUrl.empty())
                                                            {
                                                                body["code_url"] =
                                                                    codeUrl;
                                                            }
                                                            const auto prepayId =
                                                                result.get(
                                                                    "prepay_id",
                                                                    "")
                                                                    .asString();
                                                            if (!prepayId.empty())
                                                            {
                                                                body["prepay_id"] =
                                                                    prepayId;
                                                            }
                                                            const std::string responseSnapshot =
                                                                toJsonString(body);
                                                            storeIdempotencySnapshot(
                                                                dbClient_,
                                                                idempotencyKey,
                                                                requestHash,
                                                                responseSnapshot,
                                                                idempotencyTtlSeconds_);
                                                            auto resp =
                                                                drogon::
                                                                    HttpResponse::
                                                                        newHttpJsonResponse(
                                                                            body);
                                                            (*callbackPtr)(
                                                                resp);
                                                        },
                                                        [callbackPtr](
                                                            const drogon::orm::
                                                                DrogonDbException &e) {
                                                            auto resp =
                                                                drogon::
                                                                    HttpResponse::
                                                                        newHttpResponse();
                                                            resp->setStatusCode(
                                                                drogon::k500InternalServerError);
                                                            resp->setBody(
                                                                std::string(
                                                                    "db error: ") +
                                                                e.base().what());
                                                            (*callbackPtr)(
                                                                resp);
                                                        });
                                                },
                                                [callbackPtr](
                                                    const drogon::orm::
                                                        DrogonDbException &e) {
                                                    auto resp =
                                                        drogon::HttpResponse::
                                                            newHttpResponse();
                                                    resp->setStatusCode(
                                                        drogon::k500InternalServerError);
                                                    resp->setBody(
                                                        std::string(
                                                            "db error: ") +
                                                        e.base().what());
                                                    (*callbackPtr)(resp);
                                                });
                                        },
                                        [callbackPtr](
                                            const drogon::orm::
                                                DrogonDbException &e) {
                                            auto resp =
                                                drogon::HttpResponse::
                                                    newHttpResponse();
                                            resp->setStatusCode(
                                                drogon::k500InternalServerError);
                                            resp->setBody(
                                                std::string("db error: ") +
                                                e.base().what());
                                            (*callbackPtr)(resp);
                                        });
                                },
                                [callbackPtr](
                                    const drogon::orm::DrogonDbException &e) {
                                    auto resp =
                                        drogon::HttpResponse::newHttpResponse();
                                    resp->setStatusCode(
                                        drogon::k500InternalServerError);
                                    resp->setBody(std::string("db error: ") +
                                                  e.base().what());
                                    (*callbackPtr)(resp);
                                });
                        });
                },
                [callbackPtr](const drogon::orm::DrogonDbException &e) {
                    auto resp = drogon::HttpResponse::newHttpResponse();
                    resp->setStatusCode(drogon::k500InternalServerError);
                    resp->setBody(std::string("db error: ") + e.base().what());
                    (*callbackPtr)(resp);
                });
        },
        [callbackPtr](const drogon::orm::DrogonDbException &e) {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k500InternalServerError);
            resp->setBody(std::string("db error: ") + e.base().what());
            (*callbackPtr)(resp);
        });
}

void PayPlugin::proceedRefund(
    const std::shared_ptr<std::function<void(const drogon::HttpResponsePtr &)>> &callbackPtr,
    const std::string &refundNo,
    const std::string &orderNo,
    const std::string &paymentNo,
    const std::string &amount,
    const std::string &idempotencyKey,
    const std::string &requestHash)
{
    drogon::orm::Mapper<PayOrderModel> orderMapper(dbClient_);
    auto criteria = drogon::orm::Criteria(PayOrderModel::Cols::_order_no,
                                          drogon::orm::CompareOperator::EQ,
                                          orderNo);
    orderMapper.findOne(
        criteria,
        [this,
         callbackPtr,
         refundNo,
         orderNo,
         paymentNo,
         amount,
         idempotencyKey,
         requestHash](const PayOrderModel &order) {
            const std::string orderAmount = order.getValueOfAmount();
            const std::string currency = order.getValueOfCurrency();

            int64_t refundFen = 0;
            int64_t totalFen = 0;
            if (!parseAmountToFen(amount, refundFen) ||
                !parseAmountToFen(orderAmount, totalFen))
            {
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k400BadRequest);
                resp->setBody("invalid amount format");
                (*callbackPtr)(resp);
                return;
            }

            drogon::orm::Mapper<PayRefundModel> refundMapper(dbClient_);
            PayRefundModel refund;
            refund.setRefundNo(refundNo);
            refund.setOrderNo(orderNo);
            refund.setPaymentNo(paymentNo);
            refund.setStatus("REFUND_INIT");
            refund.setAmount(amount);
            refund.setCreatedAt(trantor::Date::now());
            refund.setUpdatedAt(trantor::Date::now());

            refundMapper.insert(
                refund,
                [this,
                 callbackPtr,
                 refundNo,
                 orderNo,
                 refundFen,
                 totalFen,
                 currency,
                 idempotencyKey,
                 requestHash](const PayRefundModel &) {
                    if (!wechatClient_)
                    {
                        auto resp =
                            drogon::HttpResponse::newHttpResponse();
                        resp->setStatusCode(drogon::k501NotImplemented);
                        resp->setBody("wechat client not ready");
                        drogon::orm::Mapper<PayRefundModel> refundMapper(
                            dbClient_);
                        auto refundCriteria = drogon::orm::Criteria(
                            PayRefundModel::Cols::_refund_no,
                            drogon::orm::CompareOperator::EQ,
                            refundNo);
                        refundMapper.findOne(
                            refundCriteria,
                            [this](PayRefundModel refund) {
                                refund.setStatus("REFUND_FAIL");
                                refund.setUpdatedAt(trantor::Date::now());
                                drogon::orm::Mapper<PayRefundModel>
                                    refundUpdater(dbClient_);
                                refundUpdater.update(
                                    refund,
                                    [](const size_t) {},
                                    [](const drogon::orm::DrogonDbException &) {});
                            },
                            [](const drogon::orm::DrogonDbException &) {});
                        (*callbackPtr)(resp);
                        return;
                    }

                    Json::Value payload;
                    payload["out_trade_no"] = orderNo;
                    payload["out_refund_no"] = refundNo;
                    payload["amount"]["refund"] =
                        static_cast<Json::Int64>(refundFen);
                    payload["amount"]["total"] =
                        static_cast<Json::Int64>(totalFen);
                    payload["amount"]["currency"] = currency;

                    wechatClient_->refund(
                        payload,
                        [this,
                         callbackPtr,
                         refundNo,
                         orderNo,
                         idempotencyKey,
                         requestHash](
                            const Json::Value &result,
                            const std::string &error) {
                            if (!error.empty())
                            {
                                auto resp =
                                    drogon::HttpResponse::newHttpResponse();
                                resp->setStatusCode(
                                    drogon::k502BadGateway);
                                resp->setBody("wechat error: " + error);
                                drogon::orm::Mapper<PayRefundModel> refundMapper(
                                    dbClient_);
                                auto refundCriteria = drogon::orm::Criteria(
                                    PayRefundModel::Cols::_refund_no,
                                    drogon::orm::CompareOperator::EQ,
                                    refundNo);
                                refundMapper.findOne(
                                    refundCriteria,
                                    [this](PayRefundModel refund) {
                                        refund.setStatus("REFUND_FAIL");
                                        refund.setUpdatedAt(trantor::Date::now());
                                        drogon::orm::Mapper<PayRefundModel>
                                            refundUpdater(dbClient_);
                                        refundUpdater.update(
                                            refund,
                                            [](const size_t) {},
                                            [](const drogon::orm::DrogonDbException &) {});
                                    },
                                    [](const drogon::orm::DrogonDbException &) {});
                                (*callbackPtr)(resp);
                                return;
                            }

                            std::string refundStatus = "REFUNDING";
                            const std::string wechatStatus =
                                result.get("status", "").asString();
                            const std::string refundId =
                                result.get("refund_id", "").asString();
                            if (wechatStatus == "SUCCESS")
                            {
                                refundStatus = "REFUND_SUCCESS";
                            }
                            else if (wechatStatus == "CLOSED")
                            {
                                refundStatus = "REFUND_FAIL";
                            }

                            drogon::orm::Mapper<PayRefundModel> refundMapper(
                                dbClient_);
                            auto refundCriteria = drogon::orm::Criteria(
                                PayRefundModel::Cols::_refund_no,
                                drogon::orm::CompareOperator::EQ,
                                refundNo);
                            refundMapper.findOne(
                                refundCriteria,
                                [this,
                                 callbackPtr,
                                 refundNo,
                                 orderNo,
                                 refundStatus,
                                 result,
                                 refundId,
                                 idempotencyKey,
                                 requestHash](PayRefundModel refund) {
                                    refund.setStatus(refundStatus);
                                    refund.setChannelRefundNo(refundId);
                                    refund.setUpdatedAt(trantor::Date::now());
                                    drogon::orm::Mapper<PayRefundModel>
                                        refundUpdater(dbClient_);
                                    refundUpdater.update(
                                        refund,
                                        [this,
                                         callbackPtr,
                                         refundNo,
                                         orderNo,
                                         refundStatus,
                                         result,
                                         idempotencyKey,
                                         requestHash](const size_t) {
                                            Json::Value body;
                                            body["refund_no"] = refundNo;
                                            body["order_no"] = orderNo;
                                            body["status"] = refundStatus;
                                            body["wechat_response"] = result;
                                            const std::string responseSnapshot =
                                                toJsonString(body);
                                            storeIdempotencySnapshot(
                                                dbClient_,
                                                idempotencyKey,
                                                requestHash,
                                                responseSnapshot,
                                                idempotencyTtlSeconds_);
                                            auto resp =
                                                drogon::HttpResponse::
                                                    newHttpJsonResponse(body);
                                            (*callbackPtr)(resp);
                                        },
                                        [callbackPtr](
                                            const drogon::orm::
                                                DrogonDbException &e) {
                                            auto resp =
                                                drogon::HttpResponse::
                                                    newHttpResponse();
                                            resp->setStatusCode(
                                                drogon::k500InternalServerError);
                                            resp->setBody(
                                                std::string("db error: ") +
                                                e.base().what());
                                            (*callbackPtr)(resp);
                                        });
                                },
                                [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                    auto resp =
                                        drogon::HttpResponse::newHttpResponse();
                                    resp->setStatusCode(
                                        drogon::k500InternalServerError);
                                    resp->setBody(
                                        std::string("db error: ") +
                                        e.base().what());
                                    (*callbackPtr)(resp);
                                });
                        });
                },
                [callbackPtr](const drogon::orm::DrogonDbException &e) {
                    auto resp = drogon::HttpResponse::newHttpResponse();
                    resp->setStatusCode(drogon::k500InternalServerError);
                    resp->setBody(std::string("db error: ") + e.base().what());
                    (*callbackPtr)(resp);
                });
        },
        [callbackPtr](const drogon::orm::DrogonDbException &e) {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k404NotFound);
            resp->setBody(std::string("order not found: ") + e.base().what());
            (*callbackPtr)(resp);
        });
}

void PayPlugin::createPayment(
    const drogon::HttpRequestPtr &req,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback)
{
    if (!dbClient_)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k500InternalServerError);
        resp->setBody("db client not ready");
        callback(resp);
        return;
    }

    if (!wechatClient_)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k501NotImplemented);
        resp->setBody("wechat client not ready");
        callback(resp);
        return;
    }

    auto json = req->getJsonObject();
    if (!json)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k400BadRequest);
        resp->setBody("invalid json");
        callback(resp);
        return;
    }

    std::string userId;
    std::string amount;
    std::string title;
    if (!getRequiredString(*json, "user_id", userId) ||
        !getRequiredString(*json, "amount", amount) ||
        !getRequiredString(*json, "title", title))
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k400BadRequest);
        resp->setBody("missing user_id/amount/title");
        callback(resp);
        return;
    }

    std::string currency = (*json).get("currency", "CNY").asString();
    std::string orderNo = drogon::utils::getUuid();
    std::string paymentNo = drogon::utils::getUuid();

    int64_t totalFen = 0;
    if (!parseAmountToFen(amount, totalFen))
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k400BadRequest);
        resp->setBody("invalid amount format");
        callback(resp);
        return;
    }

    int64_t userIdValue = 0;
    try
    {
        userIdValue = std::stoll(userId);
    }
    catch (...)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k400BadRequest);
        resp->setBody("invalid user_id");
        callback(resp);
        return;
    }

    const auto rawIdempotencyKey = resolveIdempotencyKey(req);
    const std::string idempotencyKey =
        rawIdempotencyKey.empty() ? "" : "create:" + rawIdempotencyKey;
    const std::string requestHash =
        rawIdempotencyKey.empty()
            ? ""
            : drogon::utils::getSha256(std::string(req->body()));

    auto callbackPtr =
        std::make_shared<std::function<void(const drogon::HttpResponsePtr &)>>(
            std::move(callback));

    auto proceedWithCreate = [this,
                              callbackPtr,
                              orderNo,
                              paymentNo,
                              amount,
                              currency,
                              title,
                              totalFen,
                              userIdValue,
                              idempotencyKey,
                              requestHash]() {
        proceedCreatePayment(callbackPtr,
                             orderNo,
                             paymentNo,
                             amount,
                             currency,
                             title,
                             totalFen,
                             userIdValue,
                             idempotencyKey,
                             requestHash);
    };

    if (idempotencyKey.empty())
    {
        proceedWithCreate();
        return;
    }

    auto respondIdempotencyConflict = [callbackPtr]() {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k409Conflict);
        resp->setBody("idempotency key conflict");
        (*callbackPtr)(resp);
    };

    auto respondIdempotencyInProgress = [callbackPtr]() {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k409Conflict);
        resp->setBody("idempotency key in progress");
        (*callbackPtr)(resp);
    };

    auto respondIdempotencySnapshot =
        [callbackPtr, requestHash, respondIdempotencyConflict](
            const PayIdempotencyModel &row) {
            if (row.getValueOfRequestHash() != requestHash)
            {
                respondIdempotencyConflict();
                return;
            }
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            resp->setBody(row.getValueOfResponseSnapshot());
            (*callbackPtr)(resp);
        };

    auto queryIdempotencyOrProceed =
        [this,
         idempotencyKey,
         respondIdempotencySnapshot,
         proceedWithCreate]() {
            drogon::orm::Mapper<PayIdempotencyModel> idempMapper(dbClient_);
            auto idempCriteria =
                drogon::orm::Criteria(
                    PayIdempotencyModel::Cols::_idempotency_key,
                    drogon::orm::CompareOperator::EQ,
                    idempotencyKey);
            idempMapper.findOne(
                idempCriteria,
                respondIdempotencySnapshot,
                [proceedWithCreate](const drogon::orm::DrogonDbException &) {
                    proceedWithCreate();
                });
        };

    auto queryIdempotencyOrConflict =
        [this,
         idempotencyKey,
         respondIdempotencySnapshot,
         respondIdempotencyInProgress]() {
            drogon::orm::Mapper<PayIdempotencyModel> idempMapper(dbClient_);
            auto idempCriteria =
                drogon::orm::Criteria(
                    PayIdempotencyModel::Cols::_idempotency_key,
                    drogon::orm::CompareOperator::EQ,
                    idempotencyKey);
            idempMapper.findOne(
                idempCriteria,
                respondIdempotencySnapshot,
                [respondIdempotencyInProgress](
                    const drogon::orm::DrogonDbException &) {
                    respondIdempotencyInProgress();
                });
        };

    if (useRedisIdempotency_ && redisClient_)
    {
        const std::string redisKey = "pay:idempotency:" + idempotencyKey;
        redisClient_->execCommandAsync(
            [queryIdempotencyOrConflict,
             queryIdempotencyOrProceed](const drogon::nosql::RedisResult &result) {
                if (result.type() == drogon::nosql::RedisResultType::kNil)
                {
                    queryIdempotencyOrConflict();
                    return;
                }
                queryIdempotencyOrProceed();
            },
            [queryIdempotencyOrProceed](
                const drogon::nosql::RedisException &) {
                queryIdempotencyOrProceed();
            },
            "SET %s %s NX EX %d",
            redisKey.c_str(),
            requestHash.c_str(),
            static_cast<int>(idempotencyTtlSeconds_));
        return;
    }

    queryIdempotencyOrProceed();
}

void PayPlugin::queryOrder(
    const drogon::HttpRequestPtr &req,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback)
{
    if (!dbClient_)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k500InternalServerError);
        resp->setBody("db client not ready");
        callback(resp);
        return;
    }

    const auto orderNo = req->getParameter("order_no");
    if (orderNo.empty())
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k400BadRequest);
        resp->setBody("missing order_no");
        callback(resp);
        return;
    }

    auto callbackPtr =
        std::make_shared<std::function<void(const drogon::HttpResponsePtr &)>>(
            std::move(callback));

    drogon::orm::Mapper<PayOrderModel> orderMapper(dbClient_);
    auto criteria = drogon::orm::Criteria(PayOrderModel::Cols::_order_no,
                                          drogon::orm::CompareOperator::EQ,
                                          orderNo);
    orderMapper.findOne(
        criteria,
        [this, callbackPtr, orderNo](const PayOrderModel &order) mutable {
            Json::Value body;
            body["order_no"] = order.getValueOfOrderNo();
            body["amount"] = order.getValueOfAmount();
            body["currency"] = order.getValueOfCurrency();
            body["status"] = order.getValueOfStatus();
            body["channel"] = order.getValueOfChannel();
            body["title"] = order.getValueOfTitle();

            if (!wechatClient_ || body["channel"].asString() != "wechat")
            {
                auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
                (*callbackPtr)(resp);
                return;
            }

            wechatClient_->queryTransaction(
                orderNo,
                [this, callbackPtr, orderNo, body](
                    const Json::Value &result,
                    const std::string &error) mutable {
                    if (!error.empty())
                    {
                        auto resp =
                            drogon::HttpResponse::newHttpJsonResponse(body);
                        resp->addHeader("X-Wechat-Query-Error", error);
                        (*callbackPtr)(resp);
                        return;
                    }

                    syncOrderStatusFromWechat(
                        orderNo,
                        result,
                        [callbackPtr, body, result](const std::string &status) mutable {
                            Json::Value out = body;
                            if (!status.empty())
                            {
                                out["status"] = status;
                            }
                            out["wechat_response"] = result;
                            auto resp =
                                drogon::HttpResponse::newHttpJsonResponse(out);
                            (*callbackPtr)(resp);
                        });
                });
        },
        [callbackPtr](const drogon::orm::DrogonDbException &e) {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k404NotFound);
            resp->setBody(std::string("order not found: ") + e.base().what());
            (*callbackPtr)(resp);
        });
}

void PayPlugin::refund(
    const drogon::HttpRequestPtr &req,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback)
{
    if (!dbClient_)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k500InternalServerError);
        resp->setBody("db client not ready");
        callback(resp);
        return;
    }

    auto json = req->getJsonObject();
    if (!json)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k400BadRequest);
        resp->setBody("invalid json");
        callback(resp);
        return;
    }

    std::string orderNo;
    std::string amount;
    if (!getRequiredString(*json, "order_no", orderNo) ||
        !getRequiredString(*json, "amount", amount))
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k400BadRequest);
        resp->setBody("missing order_no/amount");
        callback(resp);
        return;
    }

    std::string paymentNo = (*json).get("payment_no", "").asString();
    std::string refundNo = drogon::utils::getUuid();

    const auto rawIdempotencyKey = resolveIdempotencyKey(req);
    const std::string idempotencyKey =
        rawIdempotencyKey.empty() ? "" : "refund:" + rawIdempotencyKey;
    const std::string requestHash =
        rawIdempotencyKey.empty()
            ? ""
            : drogon::utils::getSha256(std::string(req->body()));

    auto callbackPtr =
        std::make_shared<std::function<void(const drogon::HttpResponsePtr &)>>(
            std::move(callback));

    auto proceedWithRefund = [this,
                              callbackPtr,
                              refundNo,
                              orderNo,
                              paymentNo,
                              amount,
                              idempotencyKey,
                              requestHash]() {
        proceedRefund(callbackPtr,
                      refundNo,
                      orderNo,
                      paymentNo,
                      amount,
                      idempotencyKey,
                      requestHash);
    };

    if (idempotencyKey.empty())
    {
        proceedWithRefund();
        return;
    }

    auto respondIdempotencyConflict = [callbackPtr]() {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k409Conflict);
        resp->setBody("idempotency key conflict");
        (*callbackPtr)(resp);
    };

    auto respondIdempotencyInProgress = [callbackPtr]() {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k409Conflict);
        resp->setBody("idempotency key in progress");
        (*callbackPtr)(resp);
    };

    auto respondIdempotencySnapshot =
        [callbackPtr, requestHash, respondIdempotencyConflict](
            const PayIdempotencyModel &row) {
            if (row.getValueOfRequestHash() != requestHash)
            {
                respondIdempotencyConflict();
                return;
            }
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            resp->setBody(row.getValueOfResponseSnapshot());
            (*callbackPtr)(resp);
        };

    auto queryIdempotencyOrProceed =
        [this,
         idempotencyKey,
         respondIdempotencySnapshot,
         proceedWithRefund]() {
            drogon::orm::Mapper<PayIdempotencyModel> idempMapper(dbClient_);
            auto idempCriteria =
                drogon::orm::Criteria(
                    PayIdempotencyModel::Cols::_idempotency_key,
                    drogon::orm::CompareOperator::EQ,
                    idempotencyKey);
            idempMapper.findOne(
                idempCriteria,
                respondIdempotencySnapshot,
                [proceedWithRefund](const drogon::orm::DrogonDbException &) {
                    proceedWithRefund();
                });
        };

    auto queryIdempotencyOrConflict =
        [this,
         idempotencyKey,
         respondIdempotencySnapshot,
         respondIdempotencyInProgress]() {
            drogon::orm::Mapper<PayIdempotencyModel> idempMapper(dbClient_);
            auto idempCriteria =
                drogon::orm::Criteria(
                    PayIdempotencyModel::Cols::_idempotency_key,
                    drogon::orm::CompareOperator::EQ,
                    idempotencyKey);
            idempMapper.findOne(
                idempCriteria,
                respondIdempotencySnapshot,
                [respondIdempotencyInProgress](
                    const drogon::orm::DrogonDbException &) {
                    respondIdempotencyInProgress();
                });
        };

    if (useRedisIdempotency_ && redisClient_)
    {
        const std::string redisKey = "pay:idempotency:" + idempotencyKey;
        redisClient_->execCommandAsync(
            [queryIdempotencyOrConflict,
             queryIdempotencyOrProceed](const drogon::nosql::RedisResult &result) {
                if (result.type() == drogon::nosql::RedisResultType::kNil)
                {
                    queryIdempotencyOrConflict();
                    return;
                }
                queryIdempotencyOrProceed();
            },
            [queryIdempotencyOrProceed](
                const drogon::nosql::RedisException &) {
                queryIdempotencyOrProceed();
            },
            "SET %s %s NX EX %d",
            redisKey.c_str(),
            requestHash.c_str(),
            static_cast<int>(idempotencyTtlSeconds_));
        return;
    }

    queryIdempotencyOrProceed();
}

void PayPlugin::queryRefund(
    const drogon::HttpRequestPtr &req,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback)
{
    if (!dbClient_)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k500InternalServerError);
        resp->setBody("db client not ready");
        callback(resp);
        return;
    }

    const auto refundNo = req->getParameter("refund_no");
    if (refundNo.empty())
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k400BadRequest);
        resp->setBody("missing refund_no");
        callback(resp);
        return;
    }

    auto callbackPtr =
        std::make_shared<std::function<void(const drogon::HttpResponsePtr &)>>(
            std::move(callback));

    drogon::orm::Mapper<PayRefundModel> refundMapper(dbClient_);
    auto criteria = drogon::orm::Criteria(PayRefundModel::Cols::_refund_no,
                                          drogon::orm::CompareOperator::EQ,
                                          refundNo);
    refundMapper.findOne(
        criteria,
        [this, callbackPtr, refundNo](const PayRefundModel &refund) mutable {
            Json::Value body;
            body["refund_no"] = refund.getValueOfRefundNo();
            body["order_no"] = refund.getValueOfOrderNo();
            body["payment_no"] = refund.getValueOfPaymentNo();
            body["status"] = refund.getValueOfStatus();
            body["amount"] = refund.getValueOfAmount();
            body["channel_refund_no"] = refund.getValueOfChannelRefundNo();

            if (!wechatClient_)
            {
                auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
                (*callbackPtr)(resp);
                return;
            }

            wechatClient_->queryRefund(
                refundNo,
                [this, callbackPtr, body, refundNo](
                    const Json::Value &result,
                    const std::string &error) mutable {
                    if (!error.empty())
                    {
                        auto resp =
                            drogon::HttpResponse::newHttpJsonResponse(body);
                        resp->addHeader("X-Wechat-Query-Error", error);
                        (*callbackPtr)(resp);
                        return;
                    }

                    syncRefundStatusFromWechat(
                        refundNo,
                        result,
                        [callbackPtr, body, result](const std::string &status) mutable {
                            Json::Value out = body;
                            if (!status.empty())
                            {
                                out["status"] = status;
                            }
                            out["wechat_response"] = result;
                            auto resp =
                                drogon::HttpResponse::newHttpJsonResponse(out);
                            (*callbackPtr)(resp);
                        });
                });
        },
        [callbackPtr](const drogon::orm::DrogonDbException &e) {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k404NotFound);
            resp->setBody(std::string("refund not found: ") + e.base().what());
            (*callbackPtr)(resp);
        });
}

void PayPlugin::reconcileSummary(
    const drogon::HttpRequestPtr &,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback)
{
    if (!dbClient_)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k500InternalServerError);
        resp->setBody("db client not ready");
        callback(resp);
        return;
    }

    auto callbackPtr =
        std::make_shared<std::function<void(const drogon::HttpResponsePtr &)>>(
            std::move(callback));
    auto responded = std::make_shared<std::atomic<bool>>(false);
    auto pending = std::make_shared<std::atomic<int>>(2);
    auto summary = std::make_shared<Json::Value>();
    (*summary)["paying_orders"] = 0;
    (*summary)["refunding_refunds"] = 0;
    (*summary)["oldest_paying_updated"] = "";
    (*summary)["oldest_refund_updated"] = "";

    auto finishIfReady = [callbackPtr, responded, pending, summary]() {
        if (pending->fetch_sub(1) != 1)
        {
            return;
        }
        if (responded->exchange(true))
        {
            return;
        }
        auto resp = drogon::HttpResponse::newHttpJsonResponse(*summary);
        (*callbackPtr)(resp);
    };

    dbClient_->execSqlAsync(
        "SELECT COUNT(*) AS cnt, MIN(updated_at) AS oldest_updated "
        "FROM pay_order WHERE status = $1",
        [summary, finishIfReady](const drogon::orm::Result &r) {
            if (!r.empty())
            {
                const auto &row = r.front();
                (*summary)["paying_orders"] = row["cnt"].as<int64_t>();
                if (!row["oldest_updated"].isNull())
                {
                    (*summary)["oldest_paying_updated"] =
                        row["oldest_updated"].as<std::string>();
                }
            }
            finishIfReady();
        },
        [callbackPtr, responded](const drogon::orm::DrogonDbException &e) {
            if (responded->exchange(true))
            {
                return;
            }
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k500InternalServerError);
            resp->setBody(std::string("db error: ") + e.base().what());
            (*callbackPtr)(resp);
        },
        "PAYING");

    dbClient_->execSqlAsync(
        "SELECT COUNT(*) AS cnt, MIN(updated_at) AS oldest_updated "
        "FROM pay_refund WHERE status IN ($1, $2)",
        [summary, finishIfReady](const drogon::orm::Result &r) {
            if (!r.empty())
            {
                const auto &row = r.front();
                (*summary)["refunding_refunds"] = row["cnt"].as<int64_t>();
                if (!row["oldest_updated"].isNull())
                {
                    (*summary)["oldest_refund_updated"] =
                        row["oldest_updated"].as<std::string>();
                }
            }
            finishIfReady();
        },
        [callbackPtr, responded](const drogon::orm::DrogonDbException &e) {
            if (responded->exchange(true))
            {
                return;
            }
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k500InternalServerError);
            resp->setBody(std::string("db error: ") + e.base().what());
            (*callbackPtr)(resp);
        },
        "REFUND_INIT",
        "REFUNDING");
}

void PayPlugin::handleWechatCallback(
    const drogon::HttpRequestPtr &req,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback)
{
    Json::Value reply;
    auto respond = [&](drogon::HttpStatusCode code,
                       const std::string &message) {
        reply["code"] = code == drogon::k200OK ? "SUCCESS" : "FAIL";
        reply["message"] = message;
        auto resp = drogon::HttpResponse::newHttpJsonResponse(reply);
        resp->setStatusCode(code);
        callback(resp);
    };

    if (!wechatClient_)
    {
        respond(drogon::k500InternalServerError, "wechat client not ready");
        return;
    }
    if (!dbClient_)
    {
        respond(drogon::k500InternalServerError, "db client not ready");
        return;
    }

    const auto timestamp = req->getHeader("Wechatpay-Timestamp");
    const auto nonce = req->getHeader("Wechatpay-Nonce");
    const auto signature = req->getHeader("Wechatpay-Signature");
    const auto serial = req->getHeader("Wechatpay-Serial");
    const std::string body = std::string(req->body());

    if (timestamp.empty() || nonce.empty() || signature.empty() || serial.empty())
    {
        respond(drogon::k400BadRequest, "missing signature headers");
        return;
    }

    std::string verifyError;
    if (!wechatClient_->verifyCallback(timestamp, nonce, body, signature, serial,
                                       verifyError))
    {
        respond(drogon::k401Unauthorized, verifyError);
        return;
    }

    Json::CharReaderBuilder builder;
    Json::Value notifyJson;
    std::string parseErrors;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(body.data(), body.data() + body.size(), &notifyJson,
                       &parseErrors))
    {
        respond(drogon::k400BadRequest, "invalid json");
        return;
    }

    const std::string eventType =
        notifyJson.get("event_type", "").asString();
    if (eventType.empty())
    {
        respond(drogon::k400BadRequest, "missing event_type");
        return;
    }

    if (!notifyJson.isMember("resource"))
    {
        respond(drogon::k400BadRequest, "missing resource");
        return;
    }

    const auto &resource = notifyJson["resource"];
    const std::string resourceType =
        notifyJson.get("resource_type", "").asString();
    if (resourceType.empty() || resourceType != "encrypt-resource")
    {
        respond(drogon::k400BadRequest, "unsupported resource_type");
        return;
    }
    const std::string algorithm = resource.get("algorithm", "").asString();
    if (algorithm.empty() || algorithm != "AEAD_AES_256_GCM")
    {
        respond(drogon::k400BadRequest, "unsupported resource algorithm");
        return;
    }
    const std::string ciphertext = resource.get("ciphertext", "").asString();
    const std::string nonceStr = resource.get("nonce", "").asString();
    const std::string associatedData =
        resource.get("associated_data", "").asString();
    if (ciphertext.empty() || nonceStr.empty())
    {
        respond(drogon::k400BadRequest, "invalid resource");
        return;
    }

    std::string plaintext;
    std::string decryptError;
    if (!wechatClient_->decryptResource(ciphertext, nonceStr, associatedData,
                                        plaintext, decryptError))
    {
        respond(drogon::k400BadRequest, decryptError);
        return;
    }

    Json::Value plainJson;
    Json::CharReaderBuilder plainBuilder;
    std::string plainErrors;
    std::unique_ptr<Json::CharReader> plainReader(plainBuilder.newCharReader());
    if (!plainReader->parse(plaintext.data(),
                            plaintext.data() + plaintext.size(),
                            &plainJson,
                            &plainErrors))
    {
        respond(drogon::k400BadRequest, "invalid resource json");
        return;
    }

    const std::string appId =
        plainJson.get("appid", "").asString();
    const std::string mchId =
        plainJson.get("mchid", "").asString();
    if (!appId.empty() && wechatClient_ &&
        appId != wechatClient_->getAppId())
    {
        respond(drogon::k400BadRequest, "appid mismatch");
        return;
    }
    if (!mchId.empty() && wechatClient_ &&
        mchId != wechatClient_->getMchId())
    {
        respond(drogon::k400BadRequest, "mchid mismatch");
        return;
    }

    const std::string refundNo =
        plainJson.get("out_refund_no", "").asString();
    const std::string refundStatusRaw =
        plainJson.get("refund_status", "").asString();
    const std::string refundId =
        plainJson.get("refund_id", "").asString();
    const bool isRefundCallback =
        !refundNo.empty() || !refundStatusRaw.empty();

    if (isRefundCallback)
    {
        if (eventType.rfind("REFUND.", 0) != 0)
        {
            respond(drogon::k400BadRequest, "invalid refund event_type");
            return;
        }
        if (refundNo.empty() || refundStatusRaw.empty())
        {
            respond(drogon::k400BadRequest,
                    "missing refund_no/refund_status");
            return;
        }

        std::string idempotencyKey = notifyJson.get("id", "").asString();
        if (idempotencyKey.empty())
        {
            idempotencyKey = refundNo + ":" + refundStatusRaw;
        }

        auto callbackPtr =
            std::make_shared<std::function<void(const drogon::HttpResponsePtr &)>>(
                std::move(callback));

        auto proceedRefundDb = [this,
                                callbackPtr,
                                idempotencyKey,
                                refundNo,
                                refundStatusRaw,
                                refundId,
                                plaintext,
                                body,
                                plainJson]() {
            drogon::orm::Mapper<PayIdempotencyModel> idempMapper(dbClient_);
            auto idempCriteria =
                drogon::orm::Criteria(PayIdempotencyModel::Cols::_idempotency_key,
                                      drogon::orm::CompareOperator::EQ,
                                      idempotencyKey);
            idempMapper.findOne(
                idempCriteria,
                [callbackPtr](const PayIdempotencyModel &) {
                    Json::Value ok;
                    ok["code"] = "SUCCESS";
                    ok["message"] = "OK";
                    auto resp = drogon::HttpResponse::newHttpJsonResponse(ok);
                    (*callbackPtr)(resp);
                },
                [this,
                 callbackPtr,
                 idempotencyKey,
                 refundNo,
                 refundStatusRaw,
                 refundId,
                 plaintext,
                 body,
                 plainJson](const drogon::orm::DrogonDbException &) {
                    const std::string requestHash =
                        drogon::utils::getSha256(body);
                    PayIdempotencyModel idemp;
                    idemp.setIdempotencyKey(idempotencyKey);
                    idemp.setRequestHash(requestHash);
                    idemp.setResponseSnapshot(plaintext);
                    const auto now = trantor::Date::now();
                    const auto expiresAt = trantor::Date(
                        now.microSecondsSinceEpoch() +
                        static_cast<int64_t>(7) * 24 * 60 * 60 * 1000000);
                    idemp.setExpiresAt(expiresAt);

                    drogon::orm::Mapper<PayIdempotencyModel> idempInsert(dbClient_);
                    idempInsert.insert(
                        idemp,
                        [this,
                         callbackPtr,
                         refundNo,
                         refundStatusRaw,
                         refundId,
                         plaintext,
                         plainJson](const PayIdempotencyModel &) {
                            const std::string refundStatus =
                                mapRefundStatus(refundStatusRaw);
                            if (refundStatus.empty())
                            {
                                auto resp =
                                    drogon::HttpResponse::newHttpResponse();
                                resp->setStatusCode(drogon::k400BadRequest);
                                resp->setBody("invalid refund status");
                                (*callbackPtr)(resp);
                                return;
                            }

                            drogon::orm::Mapper<PayRefundModel> refundMapper(
                                dbClient_);
                            auto refundCriteria =
                                drogon::orm::Criteria(
                                    PayRefundModel::Cols::_refund_no,
                                    drogon::orm::CompareOperator::EQ,
                                    refundNo);
                            refundMapper.findOne(
                                refundCriteria,
                                [this,
                                 callbackPtr,
                                 refundStatus,
                                 refundId,
                                 plaintext,
                                 plainJson](PayRefundModel refund) {
                                    if (refund.getValueOfStatus() ==
                                        "REFUND_SUCCESS")
                                    {
                                        Json::Value ok;
                                        ok["code"] = "SUCCESS";
                                        ok["message"] = "OK";
                                        auto resp =
                                            drogon::HttpResponse::newHttpJsonResponse(
                                                ok);
                                        (*callbackPtr)(resp);
                                        return;
                                    }

                                    const auto orderNo =
                                        refund.getValueOfOrderNo();
                                    const auto paymentNo =
                                        refund.getValueOfPaymentNo();
                                    const auto refundAmount =
                                        refund.getValueOfAmount();
                                    const auto &amountJson = plainJson["amount"];
                                    const std::string notifyCurrency =
                                        amountJson.get("currency", "").asString();
                                    const int64_t notifyRefundFen =
                                        amountJson.get("refund", 0).asInt64();
                                    int64_t refundTotalFen = 0;
                                    if (!parseAmountToFen(refundAmount,
                                                          refundTotalFen) ||
                                        notifyRefundFen <= 0)
                                    {
                                        auto resp =
                                            drogon::HttpResponse::newHttpResponse();
                                        resp->setStatusCode(
                                            drogon::k400BadRequest);
                                        resp->setBody(
                                            "invalid refund amount in callback");
                                        (*callbackPtr)(resp);
                                        return;
                                    }
                                    if (notifyRefundFen != refundTotalFen)
                                    {
                                        auto resp =
                                            drogon::HttpResponse::newHttpResponse();
                                        resp->setStatusCode(
                                            drogon::k400BadRequest);
                                        resp->setBody("refund amount mismatch");
                                        (*callbackPtr)(resp);
                                        return;
                                    }

                                    drogon::orm::Mapper<PayOrderModel> orderMapper(
                                        dbClient_);
                                    auto orderCriteria =
                                        drogon::orm::Criteria(
                                            PayOrderModel::Cols::_order_no,
                                            drogon::orm::CompareOperator::EQ,
                                            orderNo);
                                    orderMapper.findOne(
                                        orderCriteria,
                                        [this,
                                         callbackPtr,
                                         refundStatus,
                                         refundId,
                                         refundAmount,
                                         orderNo,
                                         paymentNo,
                                         notifyCurrency,
                                         plaintext,
                                         refund](const PayOrderModel &order) mutable {
                                            const std::string orderCurrency =
                                                order.getValueOfCurrency();
                                            if (!notifyCurrency.empty() &&
                                                notifyCurrency != orderCurrency)
                                            {
                                                auto resp =
                                                    drogon::HttpResponse::newHttpResponse();
                                                resp->setStatusCode(
                                                    drogon::k400BadRequest);
                                                resp->setBody(
                                                    "refund currency mismatch");
                                                (*callbackPtr)(resp);
                                                return;
                                            }

                                            refund.setStatus(refundStatus);
                                            refund.setChannelRefundNo(refundId);
                                            refund.setUpdatedAt(trantor::Date::now());

                                            drogon::orm::Mapper<PayRefundModel>
                                                refundUpdater(dbClient_);
                                            refundUpdater.update(
                                                refund,
                                                [this,
                                                 callbackPtr,
                                                 refundStatus,
                                                 refundAmount,
                                                 orderNo,
                                                 paymentNo,
                                                 order](const size_t) {
                                                    if (refundStatus ==
                                                        "REFUND_SUCCESS")
                                                    {
                                                        insertLedgerEntry(
                                                            dbClient_,
                                                            order.getValueOfUserId(),
                                                            orderNo,
                                                            paymentNo,
                                                            "REFUND",
                                                            refundAmount);
                                                    }
                                                    Json::Value ok;
                                                    ok["code"] = "SUCCESS";
                                                    ok["message"] = "OK";
                                                    auto resp =
                                                        drogon::HttpResponse::
                                                            newHttpJsonResponse(ok);
                                                    (*callbackPtr)(resp);
                                                },
                                                [callbackPtr](
                                                    const drogon::orm::DrogonDbException &e) {
                                                    auto resp =
                                                        drogon::HttpResponse::
                                                            newHttpResponse();
                                                    resp->setStatusCode(
                                                        drogon::k500InternalServerError);
                                                    resp->setBody(
                                                        std::string("db error: ") +
                                                        e.base().what());
                                                    (*callbackPtr)(resp);
                                                });
                                        },
                                        [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                            auto resp =
                                                drogon::HttpResponse::newHttpResponse();
                                            resp->setStatusCode(
                                                drogon::k404NotFound);
                                            resp->setBody(
                                                std::string("order not found: ") +
                                                e.base().what());
                                            (*callbackPtr)(resp);
                                        });
                                },
                                [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                    auto resp =
                                        drogon::HttpResponse::newHttpResponse();
                                    resp->setStatusCode(drogon::k404NotFound);
                                    resp->setBody(
                                        std::string("refund not found: ") +
                                        e.base().what());
                                    (*callbackPtr)(resp);
                                });
                        },
                        [callbackPtr](const drogon::orm::DrogonDbException &e) {
                            auto resp = drogon::HttpResponse::newHttpResponse();
                            resp->setStatusCode(drogon::k500InternalServerError);
                            resp->setBody(std::string("db error: ") +
                                          e.base().what());
                            (*callbackPtr)(resp);
                        });
                });
        };

        if (useRedisIdempotency_ && redisClient_)
        {
            std::string redisKey = "pay:callback:" + idempotencyKey;
            redisClient_->execCommandAsync(
                [callbackPtr, proceedRefundDb](const drogon::nosql::RedisResult &result) {
                    if (result.type() == drogon::nosql::RedisResultType::kNil)
                    {
                        Json::Value ok;
                        ok["code"] = "SUCCESS";
                        ok["message"] = "OK";
                        auto resp = drogon::HttpResponse::newHttpJsonResponse(ok);
                        (*callbackPtr)(resp);
                        return;
                    }
                    proceedRefundDb();
                },
                [callbackPtr, proceedRefundDb](const drogon::nosql::RedisException &) {
                    proceedRefundDb();
                },
                "SET %s %s NX EX %d",
                redisKey.c_str(),
                "1",
                static_cast<int>(idempotencyTtlSeconds_));
            return;
        }

        proceedRefundDb();
        return;
    }

    const std::string orderNo =
        plainJson.get("out_trade_no", "").asString();
    const std::string transactionId =
        plainJson.get("transaction_id", "").asString();
    const std::string tradeState =
        plainJson.get("trade_state", "").asString();
    if (eventType.rfind("TRANSACTION.", 0) != 0)
    {
        respond(drogon::k400BadRequest, "invalid transaction event_type");
        return;
    }
    if (orderNo.empty() || tradeState.empty())
    {
        respond(drogon::k400BadRequest, "missing out_trade_no/trade_state");
        return;
    }
    const bool tradeStateValid =
        tradeState == "SUCCESS" || tradeState == "USERPAYING" ||
        tradeState == "NOTPAY" || tradeState == "CLOSED" ||
        tradeState == "REVOKED" || tradeState == "REFUND";
    if (!tradeStateValid)
    {
        respond(drogon::k400BadRequest, "invalid trade_state");
        return;
    }

    std::string idempotencyKey = notifyJson.get("id", "").asString();
    if (idempotencyKey.empty())
    {
        idempotencyKey = orderNo + ":" + tradeState;
    }

    auto callbackPtr =
        std::make_shared<std::function<void(const drogon::HttpResponsePtr &)>>(
            std::move(callback));

    auto proceedWithDb = [this,
                          callbackPtr,
                          idempotencyKey,
                          orderNo,
                          transactionId,
                          tradeState,
                          plaintext,
                          body,
                          signature,
                          serial,
                          plainJson]() {
        drogon::orm::Mapper<PayIdempotencyModel> idempMapper(dbClient_);
        auto idempCriteria =
            drogon::orm::Criteria(PayIdempotencyModel::Cols::_idempotency_key,
                                  drogon::orm::CompareOperator::EQ,
                                  idempotencyKey);
        idempMapper.findOne(
            idempCriteria,
            [callbackPtr](const PayIdempotencyModel &) {
                Json::Value ok;
                ok["code"] = "SUCCESS";
                ok["message"] = "OK";
                auto resp = drogon::HttpResponse::newHttpJsonResponse(ok);
                (*callbackPtr)(resp);
            },
            [this,
             callbackPtr,
             idempotencyKey,
             orderNo,
             transactionId,
             tradeState,
             plaintext,
             body,
             signature,
             serial,
             plainJson](const drogon::orm::DrogonDbException &) {
                const std::string requestHash = drogon::utils::getSha256(body);
                PayIdempotencyModel idemp;
                idemp.setIdempotencyKey(idempotencyKey);
                idemp.setRequestHash(requestHash);
                idemp.setResponseSnapshot(plaintext);
                const auto now = trantor::Date::now();
                const auto expiresAt = trantor::Date(
                    now.microSecondsSinceEpoch() +
                    static_cast<int64_t>(7) * 24 * 60 * 60 * 1000000);
                idemp.setExpiresAt(expiresAt);

                drogon::orm::Mapper<PayIdempotencyModel> idempInsert(dbClient_);
                idempInsert.insert(
                    idemp,
                    [this,
                     callbackPtr,
                     orderNo,
                     transactionId,
                     tradeState,
                     plaintext,
                     body,
                     signature,
                     serial,
                     plainJson](const PayIdempotencyModel &) {
                        drogon::orm::Mapper<PayPaymentModel> paymentMapper(
                            dbClient_);
                        auto paymentCriteria =
                            drogon::orm::Criteria(
                                PayPaymentModel::Cols::_order_no,
                                drogon::orm::CompareOperator::EQ,
                                orderNo);
                        paymentMapper.orderBy(PayPaymentModel::Cols::_created_at,
                                              drogon::orm::SortOrder::DESC)
                            .limit(1)
                            .findBy(
                                paymentCriteria,
                                [this,
                                 callbackPtr,
                                 orderNo,
                                 transactionId,
                                 tradeState,
                                 plaintext,
                                 body,
                                 signature,
                                 serial,
                                 plainJson](const std::vector<PayPaymentModel> &rows) {
                                    if (rows.empty())
                                    {
                                        auto resp =
                                            drogon::HttpResponse::newHttpResponse();
                                        resp->setStatusCode(drogon::k404NotFound);
                                        resp->setBody("payment not found");
                                        (*callbackPtr)(resp);
                                        return;
                                    }

                                    const auto payment = rows.front();
                                    const std::string paymentNo =
                                        payment.getValueOfPaymentNo();
                                    const std::string orderAmount =
                                        payment.getValueOfAmount();

                                    drogon::orm::Mapper<PayOrderModel> orderMapper(
                                        dbClient_);
                                    auto orderCriteria =
                                        drogon::orm::Criteria(
                                            PayOrderModel::Cols::_order_no,
                                            drogon::orm::CompareOperator::EQ,
                                            orderNo);
                                    orderMapper.findOne(
                                        orderCriteria,
                                        [this,
                                         callbackPtr,
                                         orderNo,
                                         paymentNo,
                                         orderAmount,
                                         transactionId,
                                         tradeState,
                                         plaintext,
                                         body,
                                         signature,
                                         serial,
                                         plainJson](const PayOrderModel &order) {
                                            const std::string orderCurrency =
                                                order.getValueOfCurrency();
                                            const auto &amountJson =
                                                plainJson["amount"];
                                            const std::string notifyCurrency =
                                                amountJson.get("currency", "")
                                                    .asString();
                                            const int64_t notifyTotalFen =
                                                amountJson.get("total", 0)
                                                    .asInt64();
                                            int64_t orderTotalFen = 0;
                                            if (!parseAmountToFen(
                                                    orderAmount, orderTotalFen) ||
                                                notifyTotalFen <= 0)
                                            {
                                                auto resp =
                                                    drogon::HttpResponse::
                                                        newHttpResponse();
                                                resp->setStatusCode(
                                                    drogon::k400BadRequest);
                                                resp->setBody(
                                                    "invalid amount in callback");
                                                (*callbackPtr)(resp);
                                                return;
                                            }
                                            if (!notifyCurrency.empty() &&
                                                notifyCurrency != orderCurrency)
                                            {
                                                auto resp =
                                                    drogon::HttpResponse::newHttpResponse();
                                                resp->setStatusCode(
                                                    drogon::k400BadRequest);
                                                resp->setBody(
                                                    "currency mismatch");
                                                (*callbackPtr)(resp);
                                                return;
                                            }
                                            if (notifyTotalFen != orderTotalFen)
                                            {
                                                auto resp =
                                                    drogon::HttpResponse::newHttpResponse();
                                                resp->setStatusCode(
                                                    drogon::k400BadRequest);
                                                resp->setBody("amount mismatch");
                                                (*callbackPtr)(resp);
                                                return;
                                            }

                                            PayCallbackModel callbackRow;
                                            callbackRow.setPaymentNo(paymentNo);
                                            callbackRow.setRawBody(body);
                                            callbackRow.setSignature(signature);
                                            callbackRow.setSerialNo(serial);
                                            callbackRow.setVerified(true);
                                            callbackRow.setProcessed(false);
                                            callbackRow.setReceivedAt(trantor::Date::now());

                                            drogon::orm::Mapper<PayCallbackModel>
                                                callbackMapper(dbClient_);
                                            callbackMapper.insert(
                                                callbackRow,
                                                [this,
                                                 callbackPtr,
                                                 orderNo,
                                                 paymentNo,
                                                 transactionId,
                                                 tradeState,
                                                 plaintext](const PayCallbackModel &) {
                                                    std::string orderStatus;
                                                    std::string paymentStatus;
                                                    mapTradeState(tradeState,
                                                                  orderStatus,
                                                                  paymentStatus);

                                    drogon::orm::Mapper<PayPaymentModel>
                                        paymentMapper(dbClient_);
                                    auto payCriteria = drogon::orm::Criteria(
                                        PayPaymentModel::Cols::_payment_no,
                                        drogon::orm::CompareOperator::EQ,
                                        paymentNo);
                                    paymentMapper.findOne(
                                        payCriteria,
                                        [this,
                                         callbackPtr,
                                         orderNo,
                                         paymentNo,
                                         orderStatus,
                                         paymentStatus,
                                         transactionId,
                                         plaintext](PayPaymentModel payment) {
                                            payment.setStatus(paymentStatus);
                                            payment.setChannelTradeNo(
                                                transactionId);
                                            payment.setResponsePayload(
                                                plaintext);
                                            payment.setUpdatedAt(
                                                trantor::Date::now());
                                            drogon::orm::Mapper<PayPaymentModel>
                                                paymentUpdater(dbClient_);
                                            paymentUpdater.update(
                                                payment,
                                                [this,
                                                 callbackPtr,
                                                 orderNo,
                                                 paymentNo,
                                                 orderStatus](const size_t) {
                                                    drogon::orm::Mapper<
                                                        PayOrderModel>
                                                        orderMapper(dbClient_);
                                                    auto orderCriteria =
                                                        drogon::orm::Criteria(
                                                            PayOrderModel::Cols::
                                                                _order_no,
                                                            drogon::orm::
                                                                CompareOperator::EQ,
                                                            orderNo);
                                                    orderMapper.findOne(
                                                        orderCriteria,
                                                        [this,
                                                         callbackPtr,
                                                         paymentNo,
                                                         orderStatus](PayOrderModel order) {
                                                            const auto userId =
                                                                order.getValueOfUserId();
                                                            const auto orderAmount =
                                                                order.getValueOfAmount();
                                                            const auto orderNo =
                                                                order.getValueOfOrderNo();
                                                            order.setStatus(
                                                                orderStatus);
                                                            order.setUpdatedAt(
                                                                trantor::Date::now());
                                                            drogon::orm::Mapper<
                                                                PayOrderModel>
                                                                orderUpdater(
                                                                    dbClient_);
                                                            orderUpdater.update(
                                                                order,
                                                                [this,
                                                                 callbackPtr,
                                                                 paymentNo,
                                                                 orderStatus,
                                                                 userId,
                                                                 orderAmount,
                                                                 orderNo](const size_t) {
                                                                    if (orderStatus ==
                                                                        "PAID")
                                                                    {
                                                                        insertLedgerEntry(
                                                                            dbClient_,
                                                                            userId,
                                                                            orderNo,
                                                                            paymentNo,
                                                                            "PAYMENT",
                                                                            orderAmount);
                                                                    }
                                                                    drogon::orm::
                                                                        Mapper<
                                                                            PayCallbackModel>
                                                                            callbackMapper(
                                                                                dbClient_);
                                                                    auto cbCriteria =
                                                                        drogon::orm::Criteria(
                                                                            PayCallbackModel::Cols::
                                                                                _payment_no,
                                                                            drogon::orm::
                                                                                CompareOperator::EQ,
                                                                            paymentNo) &&
                                                                        drogon::orm::Criteria(
                                                                            PayCallbackModel::Cols::
                                                                                _processed,
                                                                            drogon::orm::
                                                                                CompareOperator::EQ,
                                                                            false);
                                                                    callbackMapper.findOne(
                                                                        cbCriteria,
                                                                        [this, callbackPtr](PayCallbackModel cb) {
                                                                            cb.setProcessed(true);
                                                                            drogon::orm::Mapper<
                                                                                PayCallbackModel>
                                                                                callbackUpdater(
                                                                                    dbClient_);
                                                                            callbackUpdater.update(
                                                                                cb,
                                                                                [callbackPtr](const size_t) {
                                                                                    Json::Value ok;
                                                                                    ok["code"] =
                                                                                        "SUCCESS";
                                                                                    ok["message"] =
                                                                                        "OK";
                                                                                    auto resp =
                                                                                        drogon::HttpResponse::
                                                                                            newHttpJsonResponse(
                                                                                                ok);
                                                                                    (*callbackPtr)(resp);
                                                                                },
                                                                                [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                                                                    auto resp =
                                                                                        drogon::HttpResponse::
                                                                                            newHttpResponse();
                                                                                    resp->setStatusCode(
                                                                                        drogon::k500InternalServerError);
                                                                                    resp->setBody(
                                                                                        std::string(
                                                                                            "db error: ") +
                                                                                        e.base().what());
                                                                                    (*callbackPtr)(resp);
                                                });
                                        },
                                        [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                            auto resp =
                                                drogon::HttpResponse::newHttpResponse();
                                            resp->setStatusCode(
                                                drogon::k500InternalServerError);
                                            resp->setBody(
                                                std::string("db error: ") +
                                                e.base().what());
                                            (*callbackPtr)(resp);
                                        });
                                                                        },
                                                                        [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                                                            auto resp =
                                                                                drogon::HttpResponse::
                                                                                    newHttpResponse();
                                                                            resp->setStatusCode(
                                                                                drogon::k500InternalServerError);
                                                                            resp->setBody(
                                                                                std::string(
                                                                                    "db error: ") +
                                                                                e.base().what());
                                                                            (*callbackPtr)(resp);
                                                                        });
                                                                },
                                                                [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                                                    auto resp =
                                                                        drogon::HttpResponse::
                                                                            newHttpResponse();
                                                                    resp->setStatusCode(
                                                                        drogon::k500InternalServerError);
                                                                    resp->setBody(
                                                                        std::string(
                                                                            "db error: ") +
                                                                        e.base().what());
                                                                    (*callbackPtr)(resp);
                                                                });
                                                        },
                                                        [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                                            auto resp =
                                                                drogon::HttpResponse::
                                                                    newHttpResponse();
                                                            resp->setStatusCode(
                                                                drogon::k500InternalServerError);
                                                            resp->setBody(
                                                                std::string(
                                                                    "db error: ") +
                                                                e.base().what());
                                                            (*callbackPtr)(resp);
                                                        });
                                                },
                                                [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                                    auto resp =
                                                        drogon::HttpResponse::
                                                            newHttpResponse();
                                                    resp->setStatusCode(
                                                        drogon::k500InternalServerError);
                                                    resp->setBody(
                                                        std::string("db error: ") +
                                                        e.base().what());
                                                    (*callbackPtr)(resp);
                                                });
                                        },
                                        [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                            auto resp =
                                                drogon::HttpResponse::newHttpResponse();
                                            resp->setStatusCode(
                                                drogon::k500InternalServerError);
                                            resp->setBody(
                                                std::string("db error: ") +
                                                e.base().what());
                                            (*callbackPtr)(resp);
                                        });
                                },
                                [callbackPtr](
                                    const drogon::orm::DrogonDbException &e) {
                                    auto resp =
                                        drogon::HttpResponse::newHttpResponse();
                                    resp->setStatusCode(
                                        drogon::k500InternalServerError);
                                    resp->setBody(std::string("db error: ") +
                                                  e.base().what());
                                    (*callbackPtr)(resp);
                                });
                            },
                            [callbackPtr](const drogon::orm::DrogonDbException &e) {
                                auto resp =
                                    drogon::HttpResponse::newHttpResponse();
                                resp->setStatusCode(
                                    drogon::k500InternalServerError);
                                resp->setBody(std::string("db error: ") +
                                              e.base().what());
                                (*callbackPtr)(resp);
                            });
                    },
                    [callbackPtr](const drogon::orm::DrogonDbException &e) {
                        auto resp = drogon::HttpResponse::newHttpResponse();
                        resp->setStatusCode(drogon::k500InternalServerError);
                        resp->setBody(std::string("db error: ") +
                                      e.base().what());
                        (*callbackPtr)(resp);
                    });
            });
    };

    if (useRedisIdempotency_ && redisClient_)
    {
        std::string redisKey = "pay:callback:" + idempotencyKey;
        redisClient_->execCommandAsync(
            [callbackPtr, proceedWithDb](const drogon::nosql::RedisResult &result) {
                if (result.type() == drogon::nosql::RedisResultType::kNil)
                {
                    Json::Value ok;
                    ok["code"] = "SUCCESS";
                    ok["message"] = "OK";
                    auto resp = drogon::HttpResponse::newHttpJsonResponse(ok);
                    (*callbackPtr)(resp);
                    return;
                }
                proceedWithDb();
            },
            [callbackPtr, proceedWithDb](const drogon::nosql::RedisException &) {
                proceedWithDb();
            },
            "SET %s %s NX EX %d",
            redisKey.c_str(),
            "1",
            static_cast<int>(idempotencyTtlSeconds_));
        return;
    }

    proceedWithDb();
}


