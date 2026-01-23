#include <drogon/drogon_test.h>
#include <drogon/nosql/RedisClient.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Mapper.h>
#include <drogon/utils/Utilities.h>
#include "../models/PayCallback.h"
#include "../models/PayIdempotency.h"
#include "../models/PayLedger.h"
#include "../models/PayOrder.h"
#include "../models/PayPayment.h"
#include "../models/PayRefund.h"
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

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

DROGON_TEST(PayIdempotency_DbUniqueKey)
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

    const std::string key = "test_" + drogon::utils::getUuid();

    client->execSqlSync(
        "INSERT INTO pay_idempotency (idempotency_key, request_hash, "
        "response_snapshot, expires_at) VALUES ($1, $2, $3, NOW() + "
        "INTERVAL '1 day')",
        key,
        "hash",
        "{}");

    bool uniqueHit = false;
    try
    {
        client->execSqlSync(
            "INSERT INTO pay_idempotency (idempotency_key, request_hash, "
            "response_snapshot, expires_at) VALUES ($1, $2, $3, NOW() + "
            "INTERVAL '1 day')",
            key,
            "hash2",
            "{}");
    }
    catch (const drogon::orm::DrogonDbException &)
    {
        uniqueHit = true;
    }

    CHECK(uniqueHit);

    client->execSqlSync("DELETE FROM pay_idempotency WHERE idempotency_key = $1",
                        key);
}

DROGON_TEST(PayIdempotency_RedisSetNx)
{
    Json::Value root;
    CHECK(loadConfig(root));
    CHECK(root.isMember("redis_clients"));
    CHECK(root["redis_clients"].isArray());
    CHECK(!root["redis_clients"].empty());

    const auto &redis = root["redis_clients"][0];
    const std::string host = redis.get("host", "127.0.0.1").asString();
    const int port = redis.get("port", 6379).asInt();
    const std::string password = redis.get("passwd", "").asString();
    const unsigned int db = redis.get("db", 0).asUInt();
    const std::string username = redis.get("username", "").asString();

    trantor::InetAddress addr(host, static_cast<uint16_t>(port));
    auto client = drogon::nosql::RedisClient::newRedisClient(
        addr, 1, password, db, username);
    CHECK(client != nullptr);

    const std::string key = "pay:test:idemp:" + drogon::utils::getUuid();

    const auto first = client->execCommandSync<std::string>(
        [](const drogon::nosql::RedisResult &r) { return r.asString(); },
        "SET %s %s NX EX %d",
        key.c_str(),
        "1",
        60);
    CHECK(first == "OK");

    const auto second = client->execCommandSync<std::string>(
        [](const drogon::nosql::RedisResult &r) {
            if (r.type() == drogon::nosql::RedisResultType::kNil)
            {
                return std::string("NIL");
            }
            return r.asString();
        },
        "SET %s %s NX EX %d",
        key.c_str(),
        "1",
        60);
    CHECK(second == "NIL");

    client->execCommandSync<int>(
        [](const drogon::nosql::RedisResult &r) {
            return static_cast<int>(r.asInteger());
        },
        "DEL %s",
        key.c_str());
}

DROGON_TEST(PayIdempotency_OrmRoundTrip)
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

    using PayIdempotency = drogon_model::pay_test::PayIdempotency;
    drogon::orm::Mapper<PayIdempotency> mapper(client);

    const std::string key = "orm_" + drogon::utils::getUuid();
    PayIdempotency row;
    row.setIdempotencyKey(key);
    row.setRequestHash("hash");
    row.setResponseSnapshot("{\"ok\":true}");
    const auto now = trantor::Date::now();
    const auto expiresAt = trantor::Date(
        now.microSecondsSinceEpoch() + 3600LL * 1000000LL);
    row.setExpiresAt(expiresAt);

    mapper.insert(row);

    const auto fetched = mapper.findByPrimaryKey(key);
    CHECK(fetched.getValueOfIdempotencyKey() == key);
    CHECK(fetched.getValueOfRequestHash() == "hash");
    CHECK(fetched.getValueOfResponseSnapshot() == "{\"ok\":true}");

    mapper.deleteByPrimaryKey(key);
}

DROGON_TEST(PayCallback_OrmRoundTrip)
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
        "CREATE TABLE IF NOT EXISTS pay_callback ("
        "id BIGSERIAL PRIMARY KEY,"
        "payment_no VARCHAR(64) NOT NULL,"
        "raw_body TEXT NOT NULL,"
        "signature VARCHAR(512),"
        "serial_no VARCHAR(64),"
        "verified BOOLEAN NOT NULL DEFAULT FALSE,"
        "processed BOOLEAN NOT NULL DEFAULT FALSE,"
        "received_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    using PayCallback = drogon_model::pay_test::PayCallback;
    drogon::orm::Mapper<PayCallback> mapper(client);

    PayCallback row;
    row.setPaymentNo("pay_" + drogon::utils::getUuid());
    row.setRawBody("{\"resource\":{}}");
    row.setSignature("sig");
    row.setSerialNo("serial");
    row.setVerified(true);
    row.setProcessed(false);
    row.setReceivedAt(trantor::Date::now());

    mapper.insert(row);
    const auto id = row.getValueOfId();
    CHECK(id > 0);

    const auto fetched = mapper.findByPrimaryKey(id);
    CHECK(fetched.getValueOfPaymentNo() == row.getValueOfPaymentNo());
    CHECK(fetched.getValueOfRawBody() == row.getValueOfRawBody());
    CHECK(fetched.getValueOfSignature() == row.getValueOfSignature());
    CHECK(fetched.getValueOfSerialNo() == row.getValueOfSerialNo());
    CHECK(fetched.getValueOfVerified() == row.getValueOfVerified());
    CHECK(fetched.getValueOfProcessed() == row.getValueOfProcessed());

    mapper.deleteByPrimaryKey(id);
}

DROGON_TEST(PayPayment_OrmRoundTrip)
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

    using PayPayment = drogon_model::pay_test::PayPayment;
    drogon::orm::Mapper<PayPayment> mapper(client);

    const auto orderNo = "order_" + drogon::utils::getUuid();
    const auto paymentNo = "pay_" + drogon::utils::getUuid();

    PayPayment row;
    row.setOrderNo(orderNo);
    row.setPaymentNo(paymentNo);
    row.setChannelTradeNo("wx_" + drogon::utils::getUuid());
    row.setStatus("SUCCESS");
    row.setAmount("12.34");
    row.setRequestPayload("{\"request\":true}");
    row.setResponsePayload("{\"response\":true}");

    mapper.insert(row);
    const auto id = row.getValueOfId();
    CHECK(id > 0);

    const auto fetched = mapper.findByPrimaryKey(id);
    CHECK(fetched.getValueOfOrderNo() == orderNo);
    CHECK(fetched.getValueOfPaymentNo() == paymentNo);
    CHECK(fetched.getValueOfChannelTradeNo() == row.getValueOfChannelTradeNo());
    CHECK(fetched.getValueOfStatus() == "SUCCESS");
    CHECK(fetched.getValueOfAmount() == "12.34");
    CHECK(fetched.getValueOfRequestPayload() ==
          row.getValueOfRequestPayload());
    CHECK(fetched.getValueOfResponsePayload() ==
          row.getValueOfResponsePayload());

    mapper.deleteByPrimaryKey(id);
}

DROGON_TEST(PayRefund_OrmRoundTrip)
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
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    using PayRefund = drogon_model::pay_test::PayRefund;
    drogon::orm::Mapper<PayRefund> mapper(client);

    const auto refundNo = "refund_" + drogon::utils::getUuid();
    const auto orderNo = "order_" + drogon::utils::getUuid();
    const auto paymentNo = "pay_" + drogon::utils::getUuid();

    PayRefund row;
    row.setRefundNo(refundNo);
    row.setOrderNo(orderNo);
    row.setPaymentNo(paymentNo);
    row.setChannelRefundNo("wxr_" + drogon::utils::getUuid());
    row.setStatus("SUCCESS");
    row.setAmount("5.67");

    mapper.insert(row);
    const auto id = row.getValueOfId();
    CHECK(id > 0);

    const auto fetched = mapper.findByPrimaryKey(id);
    CHECK(fetched.getValueOfRefundNo() == refundNo);
    CHECK(fetched.getValueOfOrderNo() == orderNo);
    CHECK(fetched.getValueOfPaymentNo() == paymentNo);
    CHECK(fetched.getValueOfChannelRefundNo() ==
          row.getValueOfChannelRefundNo());
    CHECK(fetched.getValueOfStatus() == "SUCCESS");
    CHECK(fetched.getValueOfAmount() == "5.67");

    mapper.deleteByPrimaryKey(id);
}

DROGON_TEST(PayOrder_OrmRoundTrip)
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
        "currency VARCHAR(8) NOT NULL DEFAULT 'CNY',"
        "status VARCHAR(24) NOT NULL,"
        "channel VARCHAR(16) NOT NULL,"
        "title VARCHAR(128) NOT NULL,"
        "expire_at TIMESTAMPTZ,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> mapper(client);

    const auto orderNo = "order_" + drogon::utils::getUuid();
    const int64_t userId = 12345;
    const auto expireAt = trantor::Date::now().after(3600.0);

    PayOrder row;
    row.setOrderNo(orderNo);
    row.setUserId(userId);
    row.setAmount("9.99");
    row.setCurrency("CNY");
    row.setStatus("CREATED");
    row.setChannel("WECHAT");
    row.setTitle("Test Order");
    row.setExpireAt(expireAt);

    mapper.insert(row);
    const auto id = row.getValueOfId();
    CHECK(id > 0);

    const auto fetched = mapper.findByPrimaryKey(id);
    CHECK(fetched.getValueOfOrderNo() == orderNo);
    CHECK(fetched.getValueOfUserId() == userId);
    CHECK(fetched.getValueOfAmount() == "9.99");
    CHECK(fetched.getValueOfCurrency() == "CNY");
    CHECK(fetched.getValueOfStatus() == "CREATED");
    CHECK(fetched.getValueOfChannel() == "WECHAT");
    CHECK(fetched.getValueOfTitle() == "Test Order");

    mapper.deleteByPrimaryKey(id);
}

DROGON_TEST(PayLedger_OrmRoundTrip)
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
        "CREATE TABLE IF NOT EXISTS pay_ledger ("
        "id BIGSERIAL PRIMARY KEY,"
        "user_id BIGINT NOT NULL,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64),"
        "entry_type VARCHAR(24) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "balance DECIMAL(18,2),"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    using PayLedger = drogon_model::pay_test::PayLedger;
    drogon::orm::Mapper<PayLedger> mapper(client);

    const int64_t userId = 67890;
    const auto orderNo = "order_" + drogon::utils::getUuid();
    const auto paymentNo = "pay_" + drogon::utils::getUuid();

    PayLedger row;
    row.setUserId(userId);
    row.setOrderNo(orderNo);
    row.setPaymentNo(paymentNo);
    row.setEntryType("DEBIT");
    row.setAmount("3.21");
    row.setBalance("100.00");

    mapper.insert(row);
    const auto id = row.getValueOfId();
    CHECK(id > 0);

    const auto fetched = mapper.findByPrimaryKey(id);
    CHECK(fetched.getValueOfUserId() == userId);
    CHECK(fetched.getValueOfOrderNo() == orderNo);
    CHECK(fetched.getValueOfPaymentNo() == paymentNo);
    CHECK(fetched.getValueOfEntryType() == "DEBIT");
    CHECK(fetched.getValueOfAmount() == "3.21");
    CHECK(fetched.getValueOfBalance() == "100.00");

    mapper.deleteByPrimaryKey(id);
}
