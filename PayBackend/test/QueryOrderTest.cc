#include <drogon/drogon.h>
#include <drogon/drogon_test.h>
#include <drogon/utils/Utilities.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "../models/PayOrder.h"
#include "../models/PayPayment.h"
#include "../plugins/PayPlugin.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <thread>

namespace
{
bool loadConfig(Json::Value &root)
{
    const auto cwd = std::filesystem::current_path();
    const std::vector<std::filesystem::path> candidates = {
        cwd / "config.json",
        cwd / "test" / "Release" / "config.json",
        cwd / "Release" / "config.json",
        cwd.parent_path() / "config.json",
        cwd.parent_path() / "test" / "Release" / "config.json",
        cwd.parent_path() / "Release" / "config.json"};

    std::filesystem::path configPath;
    for (const auto &candidate : candidates)
    {
        if (std::filesystem::exists(candidate))
        {
            configPath = candidate;
            break;
        }
    }

    if (configPath.empty())
    {
        return false;
    }

    std::ifstream in(configPath.string());
    if (!in)
    {
        return false;
    }

    Json::CharReaderBuilder builder;
    std::string errors;
    const bool ok = Json::parseFromStream(builder, in, &root, &errors);
    return ok;
}

std::string buildPgConnInfo(const Json::Value &db)
{
    const std::string host = db.get("host", "").asString();
    const int port = db.get("port", 5432).asInt();
    const std::string dbname = db.get("dbname", "").asString();
    const std::string user = db.get("user", "").asString();
    const std::string passwd = db.get("passwd", "").asString();

    std::string connInfo = "host=" + host + " port=" + std::to_string(port) +
                           " dbname=" + dbname + " user=" + user;
    if (!passwd.empty())
    {
        connInfo += " password=" + passwd;
    }
    return connInfo;
}

bool writeTempPrivateKey(const std::filesystem::path &path)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
    {
        return false;
    }

    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    if (!rsa || !bn)
    {
        if (bn)
        {
            BN_free(bn);
        }
        if (rsa)
        {
            RSA_free(rsa);
        }
        EVP_PKEY_free(pkey);
        return false;
    }

    if (BN_set_word(bn, RSA_F4) != 1 ||
        RSA_generate_key_ex(rsa, 2048, bn, nullptr) != 1)
    {
        BN_free(bn);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1)
    {
        BN_free(bn);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return false;
    }
    BN_free(bn);

    std::ofstream out(path.string(), std::ios::binary);
    if (!out)
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        EVP_PKEY_free(pkey);
        return false;
    }
    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr,
                                 nullptr) != 1)
    {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        return false;
    }

    BUF_MEM *buf = nullptr;
    BIO_get_mem_ptr(bio, &buf);
    if (!buf || !buf->data || buf->length == 0)
    {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        return false;
    }

    out.write(buf->data, static_cast<std::streamsize>(buf->length));
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return static_cast<bool>(out);
}
}  // namespace

DROGON_TEST(PayPlugin_QueryOrder_NoWechatClient)
{
    Json::Value root;
    CHECK(loadConfig(root));
    CHECK(root.isMember("db_clients"));
    CHECK(root["db_clients"].isArray());
    CHECK(!root["db_clients"].empty());

    const auto &db = root["db_clients"][0];
    const std::string connInfo = buildPgConnInfo(db);
    CHECK(!connInfo.empty());

    auto client = drogon::orm::DbClient::newPgClient(connInfo, 1);
    CHECK(client != nullptr);

    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_order ("
        "id BIGSERIAL PRIMARY KEY,"
        "order_no VARCHAR(64) NOT NULL UNIQUE,"
        "user_id BIGINT NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "currency VARCHAR(16) NOT NULL,"
        "status VARCHAR(24) NOT NULL,"
        "channel VARCHAR(16) NOT NULL,"
        "title VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string amount = "19.99";

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    PayOrder order;
    order.setOrderNo(orderNo);
    order.setUserId(20001);
    order.setAmount(amount);
    order.setCurrency("CNY");
    order.setStatus("PAYING");
    order.setChannel("wechat");
    order.setTitle("Query Order");
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());
    orderMapper.insert(order);

    PayPlugin plugin;
    plugin.setTestClients(nullptr, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setParameter("order_no", orderNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryOrder(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k200OK);
    const auto respJson = resp->getJsonObject();
    CHECK(respJson != nullptr);
    CHECK((*respJson)["order_no"].asString() == orderNo);
    CHECK((*respJson)["amount"].asString() == amount);
    CHECK((*respJson)["currency"].asString() == "CNY");
    CHECK((*respJson)["status"].asString() == "PAYING");
    CHECK((*respJson)["channel"].asString() == "wechat");
    CHECK((*respJson)["title"].asString() == "Query Order");

    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);
}

DROGON_TEST(PayPlugin_QueryOrder_WechatQueryError)
{
    Json::Value root;
    CHECK(loadConfig(root));
    CHECK(root.isMember("db_clients"));
    CHECK(root["db_clients"].isArray());
    CHECK(!root["db_clients"].empty());

    const auto &db = root["db_clients"][0];
    const std::string connInfo = buildPgConnInfo(db);
    CHECK(!connInfo.empty());

    auto client = drogon::orm::DbClient::newPgClient(connInfo, 1);
    CHECK(client != nullptr);

    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_order ("
        "id BIGSERIAL PRIMARY KEY,"
        "order_no VARCHAR(64) NOT NULL UNIQUE,"
        "user_id BIGINT NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "currency VARCHAR(16) NOT NULL,"
        "status VARCHAR(24) NOT NULL,"
        "channel VARCHAR(16) NOT NULL,"
        "title VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string amount = "29.99";

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    PayOrder order;
    order.setOrderNo(orderNo);
    order.setUserId(20002);
    order.setAmount(amount);
    order.setCurrency("CNY");
    order.setStatus("PAYING");
    order.setChannel("wechat");
    order.setTitle("Query Order Error");
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());
    orderMapper.insert(order);

    Json::Value wechatConfig;
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    wechatConfig["app_id"] = "wx_app";
    wechatConfig["mch_id"] = "";
    wechatConfig["notify_url"] = "https://notify.invalid";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setParameter("order_no", orderNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryOrder(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k200OK);
    CHECK(resp->getHeader("X-Wechat-Query-Error") == "missing mch_id");
    const auto respJson = resp->getJsonObject();
    CHECK(respJson != nullptr);
    CHECK((*respJson)["order_no"].asString() == orderNo);
    CHECK((*respJson)["status"].asString() == "PAYING");

    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);
}

DROGON_TEST(PayPlugin_QueryOrder_WechatSuccess)
{
    Json::Value root;
    CHECK(loadConfig(root));
    CHECK(root.isMember("db_clients"));
    CHECK(root["db_clients"].isArray());
    CHECK(!root["db_clients"].empty());

    const auto &db = root["db_clients"][0];
    const std::string connInfo = buildPgConnInfo(db);
    CHECK(!connInfo.empty());

    auto client = drogon::orm::DbClient::newPgClient(connInfo, 1);
    CHECK(client != nullptr);

    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_order ("
        "id BIGSERIAL PRIMARY KEY,"
        "order_no VARCHAR(64) NOT NULL UNIQUE,"
        "user_id BIGINT NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "currency VARCHAR(16) NOT NULL,"
        "status VARCHAR(24) NOT NULL,"
        "channel VARCHAR(16) NOT NULL,"
        "title VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_payment ("
        "id BIGSERIAL PRIMARY KEY,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64) NOT NULL UNIQUE,"
        "channel_trade_no VARCHAR(64),"
        "status VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "request_payload TEXT,"
        "response_payload TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "49.90";

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    PayOrder order;
    order.setOrderNo(orderNo);
    order.setUserId(20003);
    order.setAmount(amount);
    order.setCurrency("CNY");
    order.setStatus("PAYING");
    order.setChannel("wechat");
    order.setTitle("Query Order Success");
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());
    orderMapper.insert(order);

    using PayPayment = drogon_model::pay_test::PayPayment;
    drogon::orm::Mapper<PayPayment> paymentMapper(client);
    PayPayment payment;
    payment.setOrderNo(orderNo);
    payment.setPaymentNo(paymentNo);
    payment.setStatus("PROCESSING");
    payment.setAmount(amount);
    payment.setCreatedAt(trantor::Date::now());
    payment.setUpdatedAt(trantor::Date::now());
    paymentMapper.insert(payment);

    const uint16_t port = 24081;
    drogon::app().addListener("127.0.0.1", port);
    drogon::app().registerHandler(
        "/v3/pay/transactions/out-trade-no/{1}",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&cb,
           const std::string &param) {
            Json::Value body;
            body["trade_state"] = "SUCCESS";
            body["transaction_id"] = "wx_txn_1";
            body["out_trade_no"] = param;
            body["trade_state_desc"] = "OK";
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            cb(resp);
        },
        {drogon::Get});

    std::thread serverThread([]() { drogon::app().run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto tempDir = std::filesystem::temp_directory_path();
    const auto keyPath =
        tempDir / ("wechatpay_key_" + drogon::utils::getUuid() + ".pem");
    CHECK(writeTempPrivateKey(keyPath));

    Json::Value wechatConfig;
    wechatConfig["api_base"] =
        "http://127.0.0.1:" + std::to_string(port);
    wechatConfig["mch_id"] = "mch_456";
    wechatConfig["serial_no"] = "SERIAL_ORDER_TEST";
    wechatConfig["private_key_path"] = keyPath.string();
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setParameter("order_no", orderNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryOrder(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k200OK);
    const auto respJson = resp->getJsonObject();
    CHECK(respJson != nullptr);
    CHECK((*respJson)["order_no"].asString() == orderNo);
    CHECK((*respJson)["status"].asString() == "PAID");
    CHECK((*respJson)["wechat_response"]["trade_state"].asString() ==
          "SUCCESS");

    const auto updatedOrder =
        orderMapper.findByPrimaryKey(order.getValueOfId());
    CHECK(updatedOrder.getValueOfStatus() == "PAID");

    const auto updatedPayment =
        paymentMapper.findByPrimaryKey(payment.getValueOfId());
    CHECK(updatedPayment.getValueOfStatus() == "SUCCESS");
    CHECK(updatedPayment.getValueOfChannelTradeNo() == "wx_txn_1");

    drogon::app().quit();
    if (serverThread.joinable())
    {
        serverThread.join();
    }

    std::error_code ec;
    std::filesystem::remove(keyPath, ec);
    client->execSqlSync("DELETE FROM pay_payment WHERE payment_no = $1",
                        paymentNo);
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);
}

DROGON_TEST(PayPlugin_QueryOrder_WechatUserPaying)
{
    Json::Value root;
    CHECK(loadConfig(root));
    CHECK(root.isMember("db_clients"));
    CHECK(root["db_clients"].isArray());
    CHECK(!root["db_clients"].empty());

    const auto &db = root["db_clients"][0];
    const std::string connInfo = buildPgConnInfo(db);
    CHECK(!connInfo.empty());

    auto client = drogon::orm::DbClient::newPgClient(connInfo, 1);
    CHECK(client != nullptr);

    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_order ("
        "id BIGSERIAL PRIMARY KEY,"
        "order_no VARCHAR(64) NOT NULL UNIQUE,"
        "user_id BIGINT NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "currency VARCHAR(16) NOT NULL,"
        "status VARCHAR(24) NOT NULL,"
        "channel VARCHAR(16) NOT NULL,"
        "title VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_payment ("
        "id BIGSERIAL PRIMARY KEY,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64) NOT NULL UNIQUE,"
        "channel_trade_no VARCHAR(64),"
        "status VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "request_payload TEXT,"
        "response_payload TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "19.00";

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    PayOrder order;
    order.setOrderNo(orderNo);
    order.setUserId(20004);
    order.setAmount(amount);
    order.setCurrency("CNY");
    order.setStatus("PAYING");
    order.setChannel("wechat");
    order.setTitle("Query Order Paying");
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());
    orderMapper.insert(order);

    using PayPayment = drogon_model::pay_test::PayPayment;
    drogon::orm::Mapper<PayPayment> paymentMapper(client);
    PayPayment payment;
    payment.setOrderNo(orderNo);
    payment.setPaymentNo(paymentNo);
    payment.setStatus("PROCESSING");
    payment.setAmount(amount);
    payment.setCreatedAt(trantor::Date::now());
    payment.setUpdatedAt(trantor::Date::now());
    paymentMapper.insert(payment);

    const uint16_t port = 24082;
    drogon::app().addListener("127.0.0.1", port);
    drogon::app().registerHandler(
        "/v3/pay/transactions/out-trade-no/{1}",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&cb,
           const std::string &param) {
            Json::Value body;
            body["trade_state"] = "USERPAYING";
            body["transaction_id"] = "wx_txn_pending";
            body["out_trade_no"] = param;
            body["trade_state_desc"] = "PAYING";
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            cb(resp);
        },
        {drogon::Get});

    std::thread serverThread([]() { drogon::app().run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto tempDir = std::filesystem::temp_directory_path();
    const auto keyPath =
        tempDir / ("wechatpay_key_" + drogon::utils::getUuid() + ".pem");
    CHECK(writeTempPrivateKey(keyPath));

    Json::Value wechatConfig;
    wechatConfig["api_base"] =
        "http://127.0.0.1:" + std::to_string(port);
    wechatConfig["mch_id"] = "mch_789";
    wechatConfig["serial_no"] = "SERIAL_ORDER_PENDING";
    wechatConfig["private_key_path"] = keyPath.string();
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setParameter("order_no", orderNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryOrder(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k200OK);
    const auto respJson = resp->getJsonObject();
    CHECK(respJson != nullptr);
    CHECK((*respJson)["order_no"].asString() == orderNo);
    CHECK((*respJson)["status"].asString() == "PAYING");
    CHECK((*respJson)["wechat_response"]["trade_state"].asString() ==
          "USERPAYING");

    const auto updatedOrder =
        orderMapper.findByPrimaryKey(order.getValueOfId());
    CHECK(updatedOrder.getValueOfStatus() == "PAYING");

    const auto updatedPayment =
        paymentMapper.findByPrimaryKey(payment.getValueOfId());
    CHECK(updatedPayment.getValueOfStatus() == "PROCESSING");
    CHECK(updatedPayment.getValueOfChannelTradeNo() == "wx_txn_pending");

    drogon::app().quit();
    if (serverThread.joinable())
    {
        serverThread.join();
    }

    std::error_code ec;
    std::filesystem::remove(keyPath, ec);
    client->execSqlSync("DELETE FROM pay_payment WHERE payment_no = $1",
                        paymentNo);
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);
}

DROGON_TEST(PayPlugin_QueryOrder_WechatNotPay)
{
    Json::Value root;
    CHECK(loadConfig(root));
    CHECK(root.isMember("db_clients"));
    CHECK(root["db_clients"].isArray());
    CHECK(!root["db_clients"].empty());

    const auto &db = root["db_clients"][0];
    const std::string connInfo = buildPgConnInfo(db);
    CHECK(!connInfo.empty());

    auto client = drogon::orm::DbClient::newPgClient(connInfo, 1);
    CHECK(client != nullptr);

    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_order ("
        "id BIGSERIAL PRIMARY KEY,"
        "order_no VARCHAR(64) NOT NULL UNIQUE,"
        "user_id BIGINT NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "currency VARCHAR(16) NOT NULL,"
        "status VARCHAR(24) NOT NULL,"
        "channel VARCHAR(16) NOT NULL,"
        "title VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_payment ("
        "id BIGSERIAL PRIMARY KEY,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64) NOT NULL UNIQUE,"
        "channel_trade_no VARCHAR(64),"
        "status VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "request_payload TEXT,"
        "response_payload TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "9.50";

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    PayOrder order;
    order.setOrderNo(orderNo);
    order.setUserId(20005);
    order.setAmount(amount);
    order.setCurrency("CNY");
    order.setStatus("PAYING");
    order.setChannel("wechat");
    order.setTitle("Query Order Notpay");
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());
    orderMapper.insert(order);

    using PayPayment = drogon_model::pay_test::PayPayment;
    drogon::orm::Mapper<PayPayment> paymentMapper(client);
    PayPayment payment;
    payment.setOrderNo(orderNo);
    payment.setPaymentNo(paymentNo);
    payment.setStatus("PROCESSING");
    payment.setAmount(amount);
    payment.setCreatedAt(trantor::Date::now());
    payment.setUpdatedAt(trantor::Date::now());
    paymentMapper.insert(payment);

    const uint16_t port = 24083;
    drogon::app().addListener("127.0.0.1", port);
    drogon::app().registerHandler(
        "/v3/pay/transactions/out-trade-no/{1}",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&cb,
           const std::string &param) {
            Json::Value body;
            body["trade_state"] = "NOTPAY";
            body["transaction_id"] = "wx_txn_notpay";
            body["out_trade_no"] = param;
            body["trade_state_desc"] = "NOTPAY";
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            cb(resp);
        },
        {drogon::Get});

    std::thread serverThread([]() { drogon::app().run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto tempDir = std::filesystem::temp_directory_path();
    const auto keyPath =
        tempDir / ("wechatpay_key_" + drogon::utils::getUuid() + ".pem");
    CHECK(writeTempPrivateKey(keyPath));

    Json::Value wechatConfig;
    wechatConfig["api_base"] =
        "http://127.0.0.1:" + std::to_string(port);
    wechatConfig["mch_id"] = "mch_990";
    wechatConfig["serial_no"] = "SERIAL_ORDER_NOTPAY";
    wechatConfig["private_key_path"] = keyPath.string();
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setParameter("order_no", orderNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryOrder(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k200OK);
    const auto respJson = resp->getJsonObject();
    CHECK(respJson != nullptr);
    CHECK((*respJson)["order_no"].asString() == orderNo);
    CHECK((*respJson)["status"].asString() == "PAYING");
    CHECK((*respJson)["wechat_response"]["trade_state"].asString() == "NOTPAY");

    const auto updatedOrder =
        orderMapper.findByPrimaryKey(order.getValueOfId());
    CHECK(updatedOrder.getValueOfStatus() == "PAYING");

    const auto updatedPayment =
        paymentMapper.findByPrimaryKey(payment.getValueOfId());
    CHECK(updatedPayment.getValueOfStatus() == "PROCESSING");
    CHECK(updatedPayment.getValueOfChannelTradeNo() == "wx_txn_notpay");

    drogon::app().quit();
    if (serverThread.joinable())
    {
        serverThread.join();
    }

    std::error_code ec;
    std::filesystem::remove(keyPath, ec);
    client->execSqlSync("DELETE FROM pay_payment WHERE payment_no = $1",
                        paymentNo);
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);
}
