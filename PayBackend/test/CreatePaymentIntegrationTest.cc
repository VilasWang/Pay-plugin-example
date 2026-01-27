#include <drogon/drogon_test.h>
#include <drogon/orm/DbClient.h>
#include <drogon/utils/Utilities.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>
#include "../models/PayIdempotency.h"
#include "../plugins/PayPlugin.h"
#include "../plugins/WechatPayClient.h"
#include "../utils/PayUtils.h"

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
    return Json::parseFromStream(builder, in, &root, &errors);
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

void ensureCreatePaymentTables(
    const std::shared_ptr<drogon::orm::DbClient> &client)
{
    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_idempotency ("
        "idempotency_key VARCHAR(64) PRIMARY KEY,"
        "request_hash TEXT NOT NULL,"
        "response_snapshot TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "expires_at TIMESTAMPTZ NOT NULL)");
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
        "payment_no VARCHAR(64) NOT NULL UNIQUE,"
        "order_no VARCHAR(64) NOT NULL,"
        "channel_trade_no VARCHAR(64),"
        "status VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "request_payload TEXT,"
        "response_payload TEXT,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
}

bool waitForOrderStatus(
    const std::shared_ptr<drogon::orm::DbClient> &client,
    const std::string &title,
    std::string &orderNo,
    const std::string &orderStatus,
    const std::string &paymentStatus)
{
    for (int i = 0; i < 40; ++i)
    {
        const auto orderRows = client->execSqlSync(
            "SELECT order_no, status FROM pay_order WHERE title = $1",
            title);
        if (!orderRows.empty())
        {
            orderNo = orderRows.front()["order_no"].as<std::string>();
            const auto currentOrderStatus =
                orderRows.front()["status"].as<std::string>();
            const auto paymentRows = client->execSqlSync(
                "SELECT status FROM pay_payment WHERE order_no = $1",
                orderNo);
            if (!paymentRows.empty())
            {
                const auto currentPaymentStatus =
                    paymentRows.front()["status"].as<std::string>();
                if (currentOrderStatus == orderStatus &&
                    currentPaymentStatus == paymentStatus)
                {
                    return true;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}
}  // namespace

DROGON_TEST(PayPlugin_CreatePayment_WechatError)
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
    ensureCreatePaymentTables(client);

    Json::Value wechatConfig;
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    wechatConfig["app_id"] = "";
    wechatConfig["mch_id"] = "";
    wechatConfig["notify_url"] = "";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    const std::string title = "CreatePayError_" + drogon::utils::getUuid();
    Json::Value payload;
    payload["user_id"] = "10001";
    payload["amount"] = "9.99";
    payload["currency"] = "CNY";
    payload["title"] = title;
    const std::string body = pay::utils::toJsonString(payload);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    req->setBody(body);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.createPayment(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k502BadGateway);
    CHECK(resp->body().find("missing appid/mchid/notify_url") != std::string::npos);

    std::string orderNo;
    CHECK(waitForOrderStatus(client, title, orderNo, "FAILED", "FAIL"));

    client->execSqlSync("DELETE FROM pay_payment WHERE order_no = $1", orderNo);
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);
}

DROGON_TEST(PayPlugin_CreatePayment_IdempotencySnapshot)
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
    ensureCreatePaymentTables(client);

    Json::Value wechatConfig;
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    wechatConfig["app_id"] = "wx_app";
    wechatConfig["mch_id"] = "mch_123";
    wechatConfig["notify_url"] = "https://notify.invalid";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    const std::string idempotencyKey = "idem_" + drogon::utils::getUuid();
    const std::string title = "CreatePayIdem_" + drogon::utils::getUuid();
    Json::Value payload;
    payload["user_id"] = "10002";
    payload["amount"] = "19.99";
    payload["currency"] = "CNY";
    payload["title"] = title;
    const std::string body = pay::utils::toJsonString(payload);
    const std::string requestHash = drogon::utils::getSha256(body);

    Json::Value snapshot;
    snapshot["order_no"] = "prev_order";
    snapshot["payment_no"] = "prev_payment";
    snapshot["status"] = "PAYING";
    const std::string snapshotBody = pay::utils::toJsonString(snapshot);

    const std::string idempKey = "create:" + idempotencyKey;
    client->execSqlSync(
        "INSERT INTO pay_idempotency "
        "(idempotency_key, request_hash, response_snapshot, expires_at) "
        "VALUES ($1, $2, $3, NOW() + INTERVAL '1 day')",
        idempKey,
        requestHash,
        snapshotBody);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    req->setBody(body);
    req->addHeader("Idempotency-Key", idempotencyKey);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.createPayment(
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
    auto json = resp->getJsonObject();
    CHECK(json != nullptr);
    CHECK((*json)["order_no"].asString() == "prev_order");
    CHECK((*json)["payment_no"].asString() == "prev_payment");
    CHECK((*json)["status"].asString() == "PAYING");

    const auto countRows = client->execSqlSync(
        "SELECT COUNT(*) AS cnt FROM pay_order WHERE title = $1",
        title);
    CHECK(!countRows.empty());
    CHECK(countRows.front()["cnt"].as<int64_t>() == 0);

    client->execSqlSync("DELETE FROM pay_idempotency WHERE idempotency_key = $1",
                        idempKey);
}

DROGON_TEST(PayPlugin_CreatePayment_IdempotencyConflict)
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
    ensureCreatePaymentTables(client);

    Json::Value wechatConfig;
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    wechatConfig["app_id"] = "wx_app";
    wechatConfig["mch_id"] = "mch_123";
    wechatConfig["notify_url"] = "https://notify.invalid";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    const std::string idempotencyKey = "idem_" + drogon::utils::getUuid();
    const std::string title = "CreatePayConflict_" + drogon::utils::getUuid();
    Json::Value payload;
    payload["user_id"] = "10003";
    payload["amount"] = "29.99";
    payload["currency"] = "CNY";
    payload["title"] = title;
    const std::string body = pay::utils::toJsonString(payload);

    const std::string idempKey = "create:" + idempotencyKey;
    client->execSqlSync(
        "INSERT INTO pay_idempotency "
        "(idempotency_key, request_hash, response_snapshot, expires_at) "
        "VALUES ($1, $2, $3, NOW() + INTERVAL '1 day')",
        idempKey,
        "other_hash",
        "{}");

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    req->setBody(body);
    req->addHeader("Idempotency-Key", idempotencyKey);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.createPayment(
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

    const auto countRows = client->execSqlSync(
        "SELECT COUNT(*) AS cnt FROM pay_order WHERE title = $1",
        title);
    CHECK(!countRows.empty());
    CHECK(countRows.front()["cnt"].as<int64_t>() == 0);

    client->execSqlSync("DELETE FROM pay_idempotency WHERE idempotency_key = $1",
                        idempKey);
}
