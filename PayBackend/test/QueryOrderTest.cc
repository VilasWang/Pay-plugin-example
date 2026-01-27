#include <drogon/drogon_test.h>
#include <drogon/utils/Utilities.h>
#include "../models/PayOrder.h"
#include "../plugins/PayPlugin.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>

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
