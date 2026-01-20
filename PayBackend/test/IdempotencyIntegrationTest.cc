#include <drogon/drogon_test.h>
#include <drogon/nosql/RedisClient.h>
#include <drogon/orm/DbClient.h>
#include <drogon/utils/Utilities.h>
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
