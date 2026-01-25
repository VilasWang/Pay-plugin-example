#include <drogon/drogon_test.h>
#include <drogon/utils/Utilities.h>
#include "../models/PayOrder.h"
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

DROGON_TEST(PayPlugin_ReconcileSummary)
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

    const auto baseOrderRows = client->execSqlSync(
        "SELECT COUNT(*) AS cnt FROM pay_order WHERE status = $1",
        "PAYING");
    const int64_t basePaying =
        baseOrderRows.empty() ? 0 : baseOrderRows.front()["cnt"].as<int64_t>();

    const auto baseRefundRows = client->execSqlSync(
        "SELECT COUNT(*) AS cnt FROM pay_refund WHERE status IN ($1, $2)",
        "REFUND_INIT",
        "REFUNDING");
    const int64_t baseRefunding =
        baseRefundRows.empty() ? 0 : baseRefundRows.front()["cnt"].as<int64_t>();

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    auto makeOrder = [&](const std::string &status) {
        PayOrder order;
        order.setOrderNo("ord_" + drogon::utils::getUuid());
        order.setUserId(10001);
        order.setAmount("9.99");
        order.setCurrency("CNY");
        order.setStatus(status);
        order.setChannel("wechat");
        order.setTitle("Test Order");
        order.setCreatedAt(trantor::Date::now());
        order.setUpdatedAt(trantor::Date::now());
        orderMapper.insert(order);
        return order;
    };

    auto paying1 = makeOrder("PAYING");
    auto paying2 = makeOrder("PAYING");
    auto paid = makeOrder("PAID");

    using PayRefund = drogon_model::pay_test::PayRefund;
    drogon::orm::Mapper<PayRefund> refundMapper(client);
    auto makeRefund = [&](const std::string &status, const std::string &orderNo) {
        PayRefund refund;
        refund.setRefundNo("refund_" + drogon::utils::getUuid());
        refund.setOrderNo(orderNo);
        refund.setPaymentNo("pay_" + drogon::utils::getUuid());
        refund.setStatus(status);
        refund.setAmount("9.99");
        refund.setCreatedAt(trantor::Date::now());
        refund.setUpdatedAt(trantor::Date::now());
        refundMapper.insert(refund);
        return refund;
    };

    auto refundInit = makeRefund("REFUND_INIT", paying1.getValueOfOrderNo());
    auto refunding = makeRefund("REFUNDING", paying2.getValueOfOrderNo());
    auto refundDone = makeRefund("REFUND_SUCCESS", paid.getValueOfOrderNo());

    PayPlugin plugin;
    plugin.setTestClients(nullptr, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.reconcileSummary(
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
    CHECK((*respJson)["paying_orders"].asInt() == basePaying + 2);
    CHECK((*respJson)["refunding_refunds"].asInt() == baseRefunding + 2);

    client->execSqlSync("DELETE FROM pay_refund WHERE refund_no = $1",
                        refundInit.getValueOfRefundNo());
    client->execSqlSync("DELETE FROM pay_refund WHERE refund_no = $1",
                        refunding.getValueOfRefundNo());
    client->execSqlSync("DELETE FROM pay_refund WHERE refund_no = $1",
                        refundDone.getValueOfRefundNo());
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1",
                        paying1.getValueOfOrderNo());
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1",
                        paying2.getValueOfOrderNo());
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1",
                        paid.getValueOfOrderNo());
}
