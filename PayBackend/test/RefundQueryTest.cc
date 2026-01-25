#include <drogon/drogon_test.h>
#include <drogon/utils/Utilities.h>
#include "../models/PayRefund.h"
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
