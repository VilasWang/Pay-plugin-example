#include <drogon/drogon.h>
#include <drogon/drogon_test.h>
#include <drogon/nosql/RedisClient.h>
#include <drogon/utils/Utilities.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "../models/PayOrder.h"
#include "../models/PayRefund.h"
#include "../plugins/PayPlugin.h"
#include "../utils/PayUtils.h"
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

drogon::nosql::RedisClientPtr buildRedisClient(const Json::Value &redis)
{
    const std::string host = redis.get("host", "127.0.0.1").asString();
    const int port = redis.get("port", 6379).asInt();
    const std::string password = redis.get("passwd", "").asString();
    const unsigned int db = redis.get("db", 0).asUInt();
    const std::string username = redis.get("username", "").asString();

    trantor::InetAddress addr(host, static_cast<uint16_t>(port));
    return drogon::nosql::RedisClient::newRedisClient(
        addr, 1, password, db, username);
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

DROGON_TEST(PayPlugin_QueryRefund_NoWechatClient)
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
        "CREATE TABLE IF NOT EXISTS pay_refund ("
        "id BIGSERIAL PRIMARY KEY,"
        "refund_no VARCHAR(64) NOT NULL UNIQUE,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64) NOT NULL,"
        "channel_refund_no VARCHAR(64),"
        "status VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "response_payload TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string refundNo = "refund_" + drogon::utils::getUuid();
    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "9.99";

    using PayRefund = drogon_model::pay_test::PayRefund;
    drogon::orm::Mapper<PayRefund> refundMapper(client);
    PayRefund refund;
    refund.setRefundNo(refundNo);
    refund.setOrderNo(orderNo);
    refund.setPaymentNo(paymentNo);
    refund.setStatus("REFUNDING");
    refund.setAmount(amount);
    refund.setCreatedAt(trantor::Date::now());
    refund.setUpdatedAt(trantor::Date::now());
    refundMapper.insert(refund);

    PayPlugin plugin;
    plugin.setTestClients(nullptr, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setParameter("refund_no", refundNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryRefund(
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
    CHECK((*respJson)["refund_no"].asString() == refundNo);
    CHECK((*respJson)["order_no"].asString() == orderNo);
    CHECK((*respJson)["payment_no"].asString() == paymentNo);
    CHECK((*respJson)["status"].asString() == "REFUNDING");
    CHECK((*respJson)["amount"].asString() == amount);

    client->execSqlSync("DELETE FROM pay_refund WHERE refund_no = $1",
                        refundNo);
}

DROGON_TEST(PayPlugin_QueryRefund_WechatQueryError)
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
        "CREATE TABLE IF NOT EXISTS pay_refund ("
        "id BIGSERIAL PRIMARY KEY,"
        "refund_no VARCHAR(64) NOT NULL UNIQUE,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64) NOT NULL,"
        "channel_refund_no VARCHAR(64),"
        "status VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "response_payload TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string refundNo = "refund_" + drogon::utils::getUuid();
    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "19.99";

    using PayRefund = drogon_model::pay_test::PayRefund;
    drogon::orm::Mapper<PayRefund> refundMapper(client);
    PayRefund refund;
    refund.setRefundNo(refundNo);
    refund.setOrderNo(orderNo);
    refund.setPaymentNo(paymentNo);
    refund.setStatus("REFUNDING");
    refund.setAmount(amount);
    refund.setCreatedAt(trantor::Date::now());
    refund.setUpdatedAt(trantor::Date::now());
    refundMapper.insert(refund);

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
    req->setParameter("refund_no", refundNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryRefund(
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
    CHECK(resp->getHeader("X-Wechat-Query-Error") ==
          "wechat pay config missing mch_id/serial_no/private_key_path");
    const auto respJson = resp->getJsonObject();
    CHECK(respJson != nullptr);
    CHECK((*respJson)["refund_no"].asString() == refundNo);
    CHECK((*respJson)["status"].asString() == "REFUNDING");

    client->execSqlSync("DELETE FROM pay_refund WHERE refund_no = $1",
                        refundNo);
}

DROGON_TEST(PayPlugin_Refund_IdempotencyConflict)
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
        "CREATE TABLE IF NOT EXISTS pay_idempotency ("
        "idempotency_key VARCHAR(64) PRIMARY KEY,"
        "request_hash TEXT NOT NULL,"
        "response_snapshot TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "expires_at TIMESTAMPTZ NOT NULL)");

    const std::string idempotencyKey = "idem_" + drogon::utils::getUuid();
    Json::Value payload;
    payload["order_no"] = "ord_" + drogon::utils::getUuid();
    payload["amount"] = "9.99";
    const std::string body = pay::utils::toJsonString(payload);

    const std::string idempKey = "refund:" + idempotencyKey;
    client->execSqlSync(
        "INSERT INTO pay_idempotency "
        "(idempotency_key, request_hash, response_snapshot, expires_at) "
        "VALUES ($1, $2, $3, NOW() + INTERVAL '1 day')",
        idempKey,
        "other_hash",
        "{}");

    PayPlugin plugin;
    plugin.setTestClients(nullptr, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    req->setBody(body);
    req->addHeader("Idempotency-Key", idempotencyKey);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.refund(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k409Conflict);
    CHECK(resp->body().find("idempotency key conflict") != std::string::npos);

    client->execSqlSync("DELETE FROM pay_idempotency WHERE idempotency_key = $1",
                        idempKey);
}

DROGON_TEST(PayPlugin_Refund_IdempotencySnapshot)
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
        "CREATE TABLE IF NOT EXISTS pay_idempotency ("
        "idempotency_key VARCHAR(64) PRIMARY KEY,"
        "request_hash TEXT NOT NULL,"
        "response_snapshot TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "expires_at TIMESTAMPTZ NOT NULL)");

    const std::string idempotencyKey = "idem_" + drogon::utils::getUuid();
    Json::Value payload;
    payload["order_no"] = "ord_" + drogon::utils::getUuid();
    payload["amount"] = "12.34";
    const std::string body = pay::utils::toJsonString(payload);
    const std::string requestHash = drogon::utils::getSha256(body);

    Json::Value snapshot;
    snapshot["refund_no"] = "refund_prev";
    snapshot["order_no"] = payload["order_no"];
    snapshot["status"] = "REFUNDING";
    const std::string snapshotBody = pay::utils::toJsonString(snapshot);

    const std::string idempKey = "refund:" + idempotencyKey;
    client->execSqlSync(
        "INSERT INTO pay_idempotency "
        "(idempotency_key, request_hash, response_snapshot, expires_at) "
        "VALUES ($1, $2, $3, NOW() + INTERVAL '1 day')",
        idempKey,
        requestHash,
        snapshotBody);

    PayPlugin plugin;
    plugin.setTestClients(nullptr, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    req->setBody(body);
    req->addHeader("Idempotency-Key", idempotencyKey);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.refund(
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
    auto respJson = resp->getJsonObject();
    CHECK(respJson != nullptr);
    CHECK((*respJson)["refund_no"].asString() == "refund_prev");
    CHECK((*respJson)["status"].asString() == "REFUNDING");

    client->execSqlSync("DELETE FROM pay_idempotency WHERE idempotency_key = $1",
                        idempKey);
}

DROGON_TEST(PayPlugin_Refund_IdempotencyInProgress)
{
    Json::Value root;
    CHECK(loadConfig(root));
    CHECK(root.isMember("db_clients"));
    CHECK(root["db_clients"].isArray());
    CHECK(!root["db_clients"].empty());
    CHECK(root.isMember("redis_clients"));
    CHECK(root["redis_clients"].isArray());
    CHECK(!root["redis_clients"].empty());

    const auto &db = root["db_clients"][0];
    const std::string connInfo = buildPgConnInfo(db);
    CHECK(!connInfo.empty());

    auto client = drogon::orm::DbClient::newPgClient(connInfo, 1);
    CHECK(client != nullptr);

    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_idempotency ("
        "idempotency_key VARCHAR(64) PRIMARY KEY,"
        "request_hash TEXT NOT NULL,"
        "response_snapshot TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "expires_at TIMESTAMPTZ NOT NULL)");

    auto redisClient = buildRedisClient(root["redis_clients"][0]);
    CHECK(redisClient != nullptr);

    const std::string idempotencyKey = "idem_" + drogon::utils::getUuid();
    Json::Value payload;
    payload["order_no"] = "ord_" + drogon::utils::getUuid();
    payload["amount"] = "1.23";
    const std::string body = pay::utils::toJsonString(payload);
    const std::string requestHash = drogon::utils::getSha256(body);

    const std::string redisKey = "pay:idempotency:refund:" + idempotencyKey;
    const auto setResult = redisClient->execCommandSync<std::string>(
        [](const drogon::nosql::RedisResult &r) {
            if (r.type() == drogon::nosql::RedisResultType::kNil)
            {
                return std::string("NIL");
            }
            return r.asString();
        },
        "SET %s %s NX EX %d",
        redisKey.c_str(),
        requestHash.c_str(),
        60);
    CHECK(setResult == "OK");

    PayPlugin plugin;
    plugin.setTestClients(nullptr, client, redisClient, true);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    req->setBody(body);
    req->addHeader("Idempotency-Key", idempotencyKey);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.refund(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k409Conflict);
    CHECK(resp->body().find("idempotency key in progress") != std::string::npos);

    redisClient->execCommandSync<int>(
        [](const drogon::nosql::RedisResult &r) {
            return static_cast<int>(r.asInteger());
        },
        "DEL %s",
        redisKey.c_str());
    client->execSqlSync("DELETE FROM pay_idempotency WHERE idempotency_key = $1",
                        "refund:" + idempotencyKey);
}

DROGON_TEST(PayPlugin_QueryRefund_WechatSuccess)
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
        "CREATE TABLE IF NOT EXISTS pay_refund ("
        "id BIGSERIAL PRIMARY KEY,"
        "refund_no VARCHAR(64) NOT NULL UNIQUE,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64) NOT NULL,"
        "channel_refund_no VARCHAR(64),"
        "status VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "response_payload TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
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
        "CREATE TABLE IF NOT EXISTS pay_ledger ("
        "id BIGSERIAL PRIMARY KEY,"
        "user_id BIGINT NOT NULL,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64),"
        "entry_type VARCHAR(16) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string refundNo = "refund_" + drogon::utils::getUuid();
    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "8.88";

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    PayOrder order;
    order.setOrderNo(orderNo);
    order.setUserId(30001);
    order.setAmount(amount);
    order.setCurrency("CNY");
    order.setStatus("PAYING");
    order.setChannel("wechat");
    order.setTitle("Refund Order");
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());
    orderMapper.insert(order);

    using PayRefund = drogon_model::pay_test::PayRefund;
    drogon::orm::Mapper<PayRefund> refundMapper(client);
    PayRefund refund;
    refund.setRefundNo(refundNo);
    refund.setOrderNo(orderNo);
    refund.setPaymentNo(paymentNo);
    refund.setStatus("REFUNDING");
    refund.setAmount(amount);
    refund.setCreatedAt(trantor::Date::now());
    refund.setUpdatedAt(trantor::Date::now());
    refundMapper.insert(refund);

    const uint16_t port = 24080;
    drogon::app().addListener("127.0.0.1", port);
    drogon::app().registerHandler(
        "/v3/refund/domestic/refunds/{1}",
        [refundNo](const drogon::HttpRequestPtr &req,
                   std::function<void(const drogon::HttpResponsePtr &)> &&cb,
                   const std::string &param) {
            Json::Value body;
            body["status"] = "SUCCESS";
            body["refund_id"] = "wx_refund_1";
            body["out_refund_no"] = param;
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
    wechatConfig["mch_id"] = "mch_123";
    wechatConfig["serial_no"] = "SERIAL_TEST";
    wechatConfig["private_key_path"] = keyPath.string();
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setParameter("refund_no", refundNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryRefund(
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
    CHECK((*respJson)["refund_no"].asString() == refundNo);
    CHECK((*respJson)["status"].asString() == "REFUND_SUCCESS");
    CHECK((*respJson)["wechat_response"]["status"].asString() == "SUCCESS");

    const auto updated = refundMapper.findByPrimaryKey(
        refund.getValueOfId());
    CHECK(updated.getValueOfStatus() == "REFUND_SUCCESS");
    CHECK(updated.getValueOfChannelRefundNo() == "wx_refund_1");
    CHECK(!updated.getValueOfResponsePayload().empty());
    {
        Json::CharReaderBuilder builder;
        std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
        Json::Value payload;
        std::string errors;
        const auto responsePayload = updated.getValueOfResponsePayload();
        CHECK(reader->parse(responsePayload.data(),
                            responsePayload.data() + responsePayload.size(),
                            &payload,
                            &errors));
        CHECK(payload.get("refund_id", "").asString() == "wx_refund_1");
        CHECK(payload.get("out_refund_no", "").asString() == refundNo);
    }

    int64_t ledgerCount = 0;
    for (int i = 0; i < 20; ++i)
    {
        const auto ledgerRows = client->execSqlSync(
            "SELECT COUNT(*) AS cnt FROM pay_ledger WHERE order_no = $1",
            orderNo);
        CHECK(!ledgerRows.empty());
        ledgerCount = ledgerRows.front()["cnt"].as<int64_t>();
        if (ledgerCount == 1)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    CHECK(ledgerCount == 1);

    drogon::app().quit();
    if (serverThread.joinable())
    {
        serverThread.join();
    }

    std::error_code ec;
    std::filesystem::remove(keyPath, ec);
    client->execSqlSync("DELETE FROM pay_ledger WHERE order_no = $1", orderNo);
    client->execSqlSync("DELETE FROM pay_refund WHERE refund_no = $1",
                        refundNo);
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);
}

DROGON_TEST(PayPlugin_QueryRefund_WechatProcessing)
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
        "CREATE TABLE IF NOT EXISTS pay_refund ("
        "id BIGSERIAL PRIMARY KEY,"
        "refund_no VARCHAR(64) NOT NULL UNIQUE,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64) NOT NULL,"
        "channel_refund_no VARCHAR(64),"
        "status VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "response_payload TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_ledger ("
        "id BIGSERIAL PRIMARY KEY,"
        "user_id BIGINT NOT NULL,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64),"
        "entry_type VARCHAR(16) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string refundNo = "refund_" + drogon::utils::getUuid();
    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "6.66";

    using PayRefund = drogon_model::pay_test::PayRefund;
    drogon::orm::Mapper<PayRefund> refundMapper(client);
    PayRefund refund;
    refund.setRefundNo(refundNo);
    refund.setOrderNo(orderNo);
    refund.setPaymentNo(paymentNo);
    refund.setStatus("REFUNDING");
    refund.setAmount(amount);
    refund.setCreatedAt(trantor::Date::now());
    refund.setUpdatedAt(trantor::Date::now());
    refundMapper.insert(refund);

    const uint16_t port = 24085;
    drogon::app().addListener("127.0.0.1", port);
    drogon::app().registerHandler(
        "/v3/refund/domestic/refunds/{1}",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&cb,
           const std::string &param) {
            Json::Value body;
            body["status"] = "PROCESSING";
            body["refund_id"] = "wx_refund_processing";
            body["out_refund_no"] = param;
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
    wechatConfig["mch_id"] = "mch_333";
    wechatConfig["serial_no"] = "SERIAL_REFUND_PROCESSING";
    wechatConfig["private_key_path"] = keyPath.string();
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setParameter("refund_no", refundNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryRefund(
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
    CHECK((*respJson)["refund_no"].asString() == refundNo);
    CHECK((*respJson)["status"].asString() == "REFUNDING");
    CHECK((*respJson)["wechat_response"]["status"].asString() ==
          "PROCESSING");

    const auto updated =
        refundMapper.findByPrimaryKey(refund.getValueOfId());
    CHECK(updated.getValueOfStatus() == "REFUNDING");
    CHECK(updated.getValueOfChannelRefundNo() == "wx_refund_processing");

    const auto ledgerRows = client->execSqlSync(
        "SELECT COUNT(*) AS cnt FROM pay_ledger WHERE order_no = $1",
        orderNo);
    CHECK(!ledgerRows.empty());
    CHECK(ledgerRows.front()["cnt"].as<int64_t>() == 0);

    drogon::app().quit();
    if (serverThread.joinable())
    {
        serverThread.join();
    }

    std::error_code ec;
    std::filesystem::remove(keyPath, ec);
    client->execSqlSync("DELETE FROM pay_refund WHERE refund_no = $1",
                        refundNo);
    client->execSqlSync("DELETE FROM pay_ledger WHERE order_no = $1", orderNo);
}

DROGON_TEST(PayPlugin_QueryRefund_WechatClosed)
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
        "CREATE TABLE IF NOT EXISTS pay_refund ("
        "id BIGSERIAL PRIMARY KEY,"
        "refund_no VARCHAR(64) NOT NULL UNIQUE,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64) NOT NULL,"
        "channel_refund_no VARCHAR(64),"
        "status VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "response_payload TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_ledger ("
        "id BIGSERIAL PRIMARY KEY,"
        "user_id BIGINT NOT NULL,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64),"
        "entry_type VARCHAR(16) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string refundNo = "refund_" + drogon::utils::getUuid();
    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "3.21";

    using PayRefund = drogon_model::pay_test::PayRefund;
    drogon::orm::Mapper<PayRefund> refundMapper(client);
    PayRefund refund;
    refund.setRefundNo(refundNo);
    refund.setOrderNo(orderNo);
    refund.setPaymentNo(paymentNo);
    refund.setStatus("REFUNDING");
    refund.setAmount(amount);
    refund.setCreatedAt(trantor::Date::now());
    refund.setUpdatedAt(trantor::Date::now());
    refundMapper.insert(refund);

    const uint16_t port = 24086;
    drogon::app().addListener("127.0.0.1", port);
    drogon::app().registerHandler(
        "/v3/refund/domestic/refunds/{1}",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&cb,
           const std::string &param) {
            Json::Value body;
            body["status"] = "CLOSED";
            body["refund_id"] = "wx_refund_closed";
            body["out_refund_no"] = param;
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
    wechatConfig["mch_id"] = "mch_444";
    wechatConfig["serial_no"] = "SERIAL_REFUND_CLOSED";
    wechatConfig["private_key_path"] = keyPath.string();
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setParameter("refund_no", refundNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryRefund(
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
    CHECK((*respJson)["refund_no"].asString() == refundNo);
    CHECK((*respJson)["status"].asString() == "REFUND_FAIL");
    CHECK((*respJson)["wechat_response"]["status"].asString() == "CLOSED");

    const auto updated =
        refundMapper.findByPrimaryKey(refund.getValueOfId());
    CHECK(updated.getValueOfStatus() == "REFUND_FAIL");
    CHECK(updated.getValueOfChannelRefundNo() == "wx_refund_closed");

    const auto ledgerRows = client->execSqlSync(
        "SELECT COUNT(*) AS cnt FROM pay_ledger WHERE order_no = $1",
        orderNo);
    CHECK(!ledgerRows.empty());
    CHECK(ledgerRows.front()["cnt"].as<int64_t>() == 0);

    drogon::app().quit();
    if (serverThread.joinable())
    {
        serverThread.join();
    }

    std::error_code ec;
    std::filesystem::remove(keyPath, ec);
    client->execSqlSync("DELETE FROM pay_refund WHERE refund_no = $1",
                        refundNo);
    client->execSqlSync("DELETE FROM pay_ledger WHERE order_no = $1", orderNo);
}

DROGON_TEST(PayPlugin_QueryRefund_WechatAbnormal)
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
        "CREATE TABLE IF NOT EXISTS pay_refund ("
        "id BIGSERIAL PRIMARY KEY,"
        "refund_no VARCHAR(64) NOT NULL UNIQUE,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64) NOT NULL,"
        "channel_refund_no VARCHAR(64),"
        "status VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "response_payload TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_ledger ("
        "id BIGSERIAL PRIMARY KEY,"
        "user_id BIGINT NOT NULL,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64),"
        "entry_type VARCHAR(16) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string refundNo = "refund_" + drogon::utils::getUuid();
    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "2.58";

    using PayRefund = drogon_model::pay_test::PayRefund;
    drogon::orm::Mapper<PayRefund> refundMapper(client);
    PayRefund refund;
    refund.setRefundNo(refundNo);
    refund.setOrderNo(orderNo);
    refund.setPaymentNo(paymentNo);
    refund.setStatus("REFUNDING");
    refund.setAmount(amount);
    refund.setCreatedAt(trantor::Date::now());
    refund.setUpdatedAt(trantor::Date::now());
    refundMapper.insert(refund);

    const uint16_t port = 24087;
    drogon::app().addListener("127.0.0.1", port);
    drogon::app().registerHandler(
        "/v3/refund/domestic/refunds/{1}",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&cb,
           const std::string &param) {
            Json::Value body;
            body["status"] = "ABNORMAL";
            body["refund_id"] = "wx_refund_abnormal";
            body["out_refund_no"] = param;
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
    wechatConfig["mch_id"] = "mch_445";
    wechatConfig["serial_no"] = "SERIAL_REFUND_ABNORMAL";
    wechatConfig["private_key_path"] = keyPath.string();
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setParameter("refund_no", refundNo);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.queryRefund(
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
    CHECK((*respJson)["refund_no"].asString() == refundNo);
    CHECK((*respJson)["status"].asString() == "REFUND_FAIL");
    CHECK((*respJson)["wechat_response"]["status"].asString() == "ABNORMAL");

    const auto updated =
        refundMapper.findByPrimaryKey(refund.getValueOfId());
    CHECK(updated.getValueOfStatus() == "REFUND_FAIL");
    CHECK(updated.getValueOfChannelRefundNo() == "wx_refund_abnormal");

    const auto ledgerRows = client->execSqlSync(
        "SELECT COUNT(*) AS cnt FROM pay_ledger WHERE order_no = $1",
        orderNo);
    CHECK(!ledgerRows.empty());
    CHECK(ledgerRows.front()["cnt"].as<int64_t>() == 0);

    drogon::app().quit();
    if (serverThread.joinable())
    {
        serverThread.join();
    }

    std::error_code ec;
    std::filesystem::remove(keyPath, ec);
    client->execSqlSync("DELETE FROM pay_refund WHERE refund_no = $1",
                        refundNo);
    client->execSqlSync("DELETE FROM pay_ledger WHERE order_no = $1", orderNo);
}
