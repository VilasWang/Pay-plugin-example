#include <drogon/drogon_test.h>
#include <drogon/utils/Utilities.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include "../models/PayCallback.h"
#include "../models/PayIdempotency.h"
#include "../models/PayLedger.h"
#include "../models/PayOrder.h"
#include "../models/PayPayment.h"
#include "../plugins/PayPlugin.h"
#include "../plugins/WechatPayClient.h"

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

std::string toJsonCompact(const Json::Value &value)
{
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, value);
}

std::string encryptAesGcm(const std::string &plaintext,
                          const std::string &nonce,
                          const std::string &aad,
                          const std::string &apiV3Key)
{
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return {};
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(),
                            nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    if (EVP_EncryptInit_ex(
            ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char *>(apiV3Key.data()),
            reinterpret_cast<const unsigned char *>(nonce.data())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int outLen = 0;
    if (!aad.empty())
    {
        if (EVP_EncryptUpdate(ctx, nullptr, &outLen,
                              reinterpret_cast<const unsigned char *>(aad.data()),
                              aad.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    }

    std::string ciphertext(plaintext.size(), '\0');
    if (EVP_EncryptUpdate(
            ctx,
            reinterpret_cast<unsigned char *>(&ciphertext[0]),
            &outLen,
            reinterpret_cast<const unsigned char *>(plaintext.data()),
            plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    int totalLen = outLen;

    if (EVP_EncryptFinal_ex(
            ctx,
            reinterpret_cast<unsigned char *>(&ciphertext[totalLen]),
            &outLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    totalLen += outLen;
    ciphertext.resize(totalLen);

    unsigned char tag[16] = {};
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.append(reinterpret_cast<const char *>(tag), sizeof(tag));
    return drogon::utils::base64Encode(ciphertext);
}

bool generateKeyAndCert(EVP_PKEY **outKey, std::string &certPem)
{
    if (!outKey)
    {
        return false;
    }
    *outKey = nullptr;

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
    {
        return false;
    }

    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    if (!rsa || !e)
    {
        RSA_free(rsa);
        BN_free(e);
        EVP_PKEY_free(pkey);
        return false;
    }

    if (BN_set_word(e, RSA_F4) != 1 ||
        RSA_generate_key_ex(rsa, 2048, e, nullptr) != 1 ||
        EVP_PKEY_assign_RSA(pkey, rsa) != 1)
    {
        RSA_free(rsa);
        BN_free(e);
        EVP_PKEY_free(pkey);
        return false;
    }
    BN_free(e);

    X509 *cert = X509_new();
    if (!cert)
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60);
    X509_set_pubkey(cert, pkey);

    auto subjectName = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(subjectName, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>("Test"),
                               -1, -1, 0);
    X509_set_issuer_name(cert, subjectName);

    if (X509_sign(cert, pkey, EVP_sha256()) == 0)
    {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return false;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return false;
    }
    if (PEM_write_bio_X509(bio, cert) != 1)
    {
        BIO_free(bio);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return false;
    }

    BUF_MEM *buf = nullptr;
    BIO_get_mem_ptr(bio, &buf);
    if (!buf || !buf->data || buf->length == 0)
    {
        BIO_free(bio);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return false;
    }

    certPem.assign(buf->data, buf->length);
    BIO_free(bio);
    X509_free(cert);
    *outKey = pkey;
    return true;
}

bool signMessage(const std::string &message,
                 EVP_PKEY *pkey,
                 std::string &signatureB64)
{
    if (!pkey)
    {
        return false;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return false;
    }
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    size_t sigLen = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    std::string signature(sigLen, '\0');
    if (EVP_DigestSignFinal(
            ctx, reinterpret_cast<unsigned char *>(&signature[0]), &sigLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    EVP_MD_CTX_free(ctx);
    signature.resize(sigLen);
    signatureB64 = drogon::utils::base64Encode(signature);
    return true;
}
}  // namespace

DROGON_TEST(PayPlugin_WechatCallback_EndToEnd)
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
        "request_hash VARCHAR(64) NOT NULL,"
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
    client->execSqlSync(
        "ALTER TABLE pay_callback "
        "ALTER COLUMN signature TYPE VARCHAR(512)");
    client->execSqlSync(
        "CREATE TABLE IF NOT EXISTS pay_ledger ("
        "id BIGSERIAL PRIMARY KEY,"
        "user_id BIGINT NOT NULL,"
        "order_no VARCHAR(64) NOT NULL,"
        "payment_no VARCHAR(64),"
        "entry_type VARCHAR(16) NOT NULL,"
        "amount DECIMAL(18,2) NOT NULL,"
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");

    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "9.99";

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    PayOrder order;
    order.setOrderNo(orderNo);
    order.setUserId(10001);
    order.setAmount(amount);
    order.setCurrency("CNY");
    order.setStatus("PAYING");
    order.setChannel("wechat");
    order.setTitle("Test Order");
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());
    orderMapper.insert(order);

    using PayPayment = drogon_model::pay_test::PayPayment;
    drogon::orm::Mapper<PayPayment> paymentMapper(client);
    PayPayment payment;
    payment.setPaymentNo(paymentNo);
    payment.setOrderNo(orderNo);
    payment.setStatus("PROCESSING");
    payment.setAmount(amount);
    payment.setRequestPayload("{}");
    payment.setCreatedAt(trantor::Date::now());
    payment.setUpdatedAt(trantor::Date::now());
    paymentMapper.insert(payment);

    EVP_PKEY *pkey = nullptr;
    std::string certPem;
    CHECK(generateKeyAndCert(&pkey, certPem));

    const auto tempDir = std::filesystem::temp_directory_path();
    const auto certPath =
        tempDir / ("wechatpay_cb_" + drogon::utils::getUuid() + ".pem");
    {
        std::ofstream out(certPath.string(), std::ios::binary);
        out << certPem;
    }

    const std::string apiV3Key = "0123456789abcdef0123456789abcdef";
    Json::Value wechatConfig;
    wechatConfig["api_v3_key"] = apiV3Key;
    wechatConfig["platform_cert_path"] = certPath.string();
    wechatConfig["serial_no"] = "SERIAL_TEST";
    wechatConfig["app_id"] = "wx_app";
    wechatConfig["mch_id"] = "mch_123";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    Json::Value plain;
    plain["out_trade_no"] = orderNo;
    plain["transaction_id"] = "tx_" + drogon::utils::getUuid();
    plain["trade_state"] = "SUCCESS";
    plain["appid"] = wechatConfig["app_id"].asString();
    plain["mchid"] = wechatConfig["mch_id"].asString();
    plain["amount"]["total"] = 999;
    plain["amount"]["currency"] = "CNY";
    const std::string plainText = toJsonCompact(plain);

    const std::string nonce = "nonce123";
    const std::string aad = "transaction";
    const std::string ciphertext = encryptAesGcm(plainText, nonce, aad, apiV3Key);
    CHECK(!ciphertext.empty());

    Json::Value notify;
    notify["id"] = "notify_" + drogon::utils::getUuid();
    notify["event_type"] = "TRANSACTION.SUCCESS";
    notify["resource_type"] = "encrypt-resource";
    notify["resource"]["algorithm"] = "AEAD_AES_256_GCM";
    notify["resource"]["ciphertext"] = ciphertext;
    notify["resource"]["nonce"] = nonce;
    notify["resource"]["associated_data"] = aad;
    const std::string body = toJsonCompact(notify);

    const std::string timestamp = "1700000000";
    const std::string headerNonce = "headerNonce";
    const std::string message =
        timestamp + "\n" + headerNonce + "\n" + body + "\n";
    std::string signatureB64;
    CHECK(signMessage(message, pkey, signatureB64));

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setBody(body);
    req->addHeader("Wechatpay-Timestamp", timestamp);
    req->addHeader("Wechatpay-Nonce", headerNonce);
    req->addHeader("Wechatpay-Signature", signatureB64);
    req->addHeader("Wechatpay-Serial", "SERIAL_TEST");

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.handleWechatCallback(
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
    CHECK((*respJson)["code"].asString() == "SUCCESS");

    const auto updatedPayment = paymentMapper.findByPrimaryKey(
        payment.getValueOfId());
    CHECK(updatedPayment.getValueOfStatus() == "SUCCESS");

    const auto updatedOrder = orderMapper.findByPrimaryKey(
        order.getValueOfId());
    CHECK(updatedOrder.getValueOfStatus() == "PAID");

    const auto callbackRows = client->execSqlSync(
        "SELECT processed FROM pay_callback WHERE payment_no = $1",
        paymentNo);
    CHECK(callbackRows.size() >= 1);
    CHECK(callbackRows.front()["processed"].as<bool>());

    const auto ledgerRows = client->execSqlSync(
        "SELECT entry_type FROM pay_ledger WHERE order_no = $1",
        orderNo);
    CHECK(ledgerRows.size() >= 1);
    CHECK(ledgerRows.front()["entry_type"].as<std::string>() == "PAYMENT");

    client->execSqlSync("DELETE FROM pay_callback WHERE payment_no = $1",
                        paymentNo);
    client->execSqlSync("DELETE FROM pay_payment WHERE payment_no = $1",
                        paymentNo);
    client->execSqlSync("DELETE FROM pay_ledger WHERE order_no = $1", orderNo);
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);
    client->execSqlSync("DELETE FROM pay_idempotency WHERE idempotency_key = $1",
                        notify["id"].asString());

    EVP_PKEY_free(pkey);
    std::error_code ec;
    std::filesystem::remove(certPath, ec);
}

DROGON_TEST(PayPlugin_WechatCallback_InvalidSignature)
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
        "request_hash VARCHAR(64) NOT NULL,"
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
    client->execSqlSync(
        "ALTER TABLE pay_callback "
        "ALTER COLUMN signature TYPE VARCHAR(512)");

    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "9.99";

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    PayOrder order;
    order.setOrderNo(orderNo);
    order.setUserId(10001);
    order.setAmount(amount);
    order.setCurrency("CNY");
    order.setStatus("PAYING");
    order.setChannel("wechat");
    order.setTitle("Test Order");
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());
    orderMapper.insert(order);

    using PayPayment = drogon_model::pay_test::PayPayment;
    drogon::orm::Mapper<PayPayment> paymentMapper(client);
    PayPayment payment;
    payment.setPaymentNo(paymentNo);
    payment.setOrderNo(orderNo);
    payment.setStatus("PROCESSING");
    payment.setAmount(amount);
    payment.setRequestPayload("{}");
    payment.setCreatedAt(trantor::Date::now());
    payment.setUpdatedAt(trantor::Date::now());
    paymentMapper.insert(payment);

    EVP_PKEY *pkey = nullptr;
    std::string certPem;
    CHECK(generateKeyAndCert(&pkey, certPem));

    const auto tempDir = std::filesystem::temp_directory_path();
    const auto certPath =
        tempDir / ("wechatpay_cb_" + drogon::utils::getUuid() + ".pem");
    {
        std::ofstream out(certPath.string(), std::ios::binary);
        out << certPem;
    }

    const std::string apiV3Key = "0123456789abcdef0123456789abcdef";
    Json::Value wechatConfig;
    wechatConfig["api_v3_key"] = apiV3Key;
    wechatConfig["platform_cert_path"] = certPath.string();
    wechatConfig["serial_no"] = "SERIAL_TEST";
    wechatConfig["app_id"] = "wx_app";
    wechatConfig["mch_id"] = "mch_123";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    Json::Value plain;
    plain["out_trade_no"] = orderNo;
    plain["transaction_id"] = "tx_" + drogon::utils::getUuid();
    plain["trade_state"] = "SUCCESS";
    plain["appid"] = wechatConfig["app_id"].asString();
    plain["mchid"] = wechatConfig["mch_id"].asString();
    plain["amount"]["total"] = 999;
    plain["amount"]["currency"] = "CNY";
    const std::string plainText = toJsonCompact(plain);

    const std::string nonce = "nonce123";
    const std::string aad = "transaction";
    const std::string ciphertext = encryptAesGcm(plainText, nonce, aad, apiV3Key);
    CHECK(!ciphertext.empty());

    Json::Value notify;
    notify["id"] = "notify_" + drogon::utils::getUuid();
    notify["event_type"] = "TRANSACTION.SUCCESS";
    notify["resource_type"] = "encrypt-resource";
    notify["resource"]["algorithm"] = "AEAD_AES_256_GCM";
    notify["resource"]["ciphertext"] = ciphertext;
    notify["resource"]["nonce"] = nonce;
    notify["resource"]["associated_data"] = aad;
    const std::string body = toJsonCompact(notify);

    const std::string timestamp = "1700000000";
    const std::string headerNonce = "headerNonce";
    std::string signatureB64;
    CHECK(signMessage("tampered\n", pkey, signatureB64));

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setBody(body);
    req->addHeader("Wechatpay-Timestamp", timestamp);
    req->addHeader("Wechatpay-Nonce", headerNonce);
    req->addHeader("Wechatpay-Signature", signatureB64);
    req->addHeader("Wechatpay-Serial", "SERIAL_TEST");

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.handleWechatCallback(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k401Unauthorized);

    const auto callbackRows = client->execSqlSync(
        "SELECT id FROM pay_callback WHERE payment_no = $1",
        paymentNo);
    CHECK(callbackRows.empty());

    const auto updatedPayment = paymentMapper.findByPrimaryKey(
        payment.getValueOfId());
    CHECK(updatedPayment.getValueOfStatus() == "PROCESSING");

    const auto updatedOrder = orderMapper.findByPrimaryKey(
        order.getValueOfId());
    CHECK(updatedOrder.getValueOfStatus() == "PAYING");

    client->execSqlSync("DELETE FROM pay_payment WHERE payment_no = $1",
                        paymentNo);
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);

    EVP_PKEY_free(pkey);
    std::error_code ec;
    std::filesystem::remove(certPath, ec);
}

DROGON_TEST(PayPlugin_WechatCallback_DecryptFailure)
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
        "request_hash VARCHAR(64) NOT NULL,"
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
    client->execSqlSync(
        "ALTER TABLE pay_callback "
        "ALTER COLUMN signature TYPE VARCHAR(512)");

    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "9.99";

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    PayOrder order;
    order.setOrderNo(orderNo);
    order.setUserId(10001);
    order.setAmount(amount);
    order.setCurrency("CNY");
    order.setStatus("PAYING");
    order.setChannel("wechat");
    order.setTitle("Test Order");
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());
    orderMapper.insert(order);

    using PayPayment = drogon_model::pay_test::PayPayment;
    drogon::orm::Mapper<PayPayment> paymentMapper(client);
    PayPayment payment;
    payment.setPaymentNo(paymentNo);
    payment.setOrderNo(orderNo);
    payment.setStatus("PROCESSING");
    payment.setAmount(amount);
    payment.setRequestPayload("{}");
    payment.setCreatedAt(trantor::Date::now());
    payment.setUpdatedAt(trantor::Date::now());
    paymentMapper.insert(payment);

    EVP_PKEY *pkey = nullptr;
    std::string certPem;
    CHECK(generateKeyAndCert(&pkey, certPem));

    const auto tempDir = std::filesystem::temp_directory_path();
    const auto certPath =
        tempDir / ("wechatpay_cb_" + drogon::utils::getUuid() + ".pem");
    {
        std::ofstream out(certPath.string(), std::ios::binary);
        out << certPem;
    }

    const std::string correctApiV3Key = "0123456789abcdef0123456789abcdef";
    Json::Value wechatConfig;
    wechatConfig["api_v3_key"] = "00000000000000000000000000000000";
    wechatConfig["platform_cert_path"] = certPath.string();
    wechatConfig["serial_no"] = "SERIAL_TEST";
    wechatConfig["app_id"] = "wx_app";
    wechatConfig["mch_id"] = "mch_123";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    Json::Value plain;
    plain["out_trade_no"] = orderNo;
    plain["transaction_id"] = "tx_" + drogon::utils::getUuid();
    plain["trade_state"] = "SUCCESS";
    plain["appid"] = wechatConfig["app_id"].asString();
    plain["mchid"] = wechatConfig["mch_id"].asString();
    plain["amount"]["total"] = 999;
    plain["amount"]["currency"] = "CNY";
    const std::string plainText = toJsonCompact(plain);

    const std::string nonce = "nonce123";
    const std::string aad = "transaction";
    const std::string ciphertext =
        encryptAesGcm(plainText, nonce, aad, correctApiV3Key);
    CHECK(!ciphertext.empty());

    Json::Value notify;
    notify["id"] = "notify_" + drogon::utils::getUuid();
    notify["event_type"] = "TRANSACTION.SUCCESS";
    notify["resource_type"] = "encrypt-resource";
    notify["resource"]["algorithm"] = "AEAD_AES_256_GCM";
    notify["resource"]["ciphertext"] = ciphertext;
    notify["resource"]["nonce"] = nonce;
    notify["resource"]["associated_data"] = aad;
    const std::string body = toJsonCompact(notify);

    const std::string timestamp = "1700000000";
    const std::string headerNonce = "headerNonce";
    const std::string message =
        timestamp + "\n" + headerNonce + "\n" + body + "\n";
    std::string signatureB64;
    CHECK(signMessage(message, pkey, signatureB64));

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setBody(body);
    req->addHeader("Wechatpay-Timestamp", timestamp);
    req->addHeader("Wechatpay-Nonce", headerNonce);
    req->addHeader("Wechatpay-Signature", signatureB64);
    req->addHeader("Wechatpay-Serial", "SERIAL_TEST");

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.handleWechatCallback(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k400BadRequest);

    const auto callbackRows = client->execSqlSync(
        "SELECT id FROM pay_callback WHERE payment_no = $1",
        paymentNo);
    CHECK(callbackRows.empty());

    const auto updatedPayment = paymentMapper.findByPrimaryKey(
        payment.getValueOfId());
    CHECK(updatedPayment.getValueOfStatus() == "PROCESSING");

    const auto updatedOrder = orderMapper.findByPrimaryKey(
        order.getValueOfId());
    CHECK(updatedOrder.getValueOfStatus() == "PAYING");

    client->execSqlSync("DELETE FROM pay_payment WHERE payment_no = $1",
                        paymentNo);
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);

    EVP_PKEY_free(pkey);
    std::error_code ec;
    std::filesystem::remove(certPath, ec);
}

DROGON_TEST(PayPlugin_WechatCallback_MissingSignatureHeaders)
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
        "request_hash VARCHAR(64) NOT NULL,"
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
    client->execSqlSync(
        "ALTER TABLE pay_callback "
        "ALTER COLUMN signature TYPE VARCHAR(512)");

    const std::string orderNo = "ord_" + drogon::utils::getUuid();
    const std::string paymentNo = "pay_" + drogon::utils::getUuid();
    const std::string amount = "9.99";

    using PayOrder = drogon_model::pay_test::PayOrder;
    drogon::orm::Mapper<PayOrder> orderMapper(client);
    PayOrder order;
    order.setOrderNo(orderNo);
    order.setUserId(10001);
    order.setAmount(amount);
    order.setCurrency("CNY");
    order.setStatus("PAYING");
    order.setChannel("wechat");
    order.setTitle("Test Order");
    order.setCreatedAt(trantor::Date::now());
    order.setUpdatedAt(trantor::Date::now());
    orderMapper.insert(order);

    using PayPayment = drogon_model::pay_test::PayPayment;
    drogon::orm::Mapper<PayPayment> paymentMapper(client);
    PayPayment payment;
    payment.setPaymentNo(paymentNo);
    payment.setOrderNo(orderNo);
    payment.setStatus("PROCESSING");
    payment.setAmount(amount);
    payment.setRequestPayload("{}");
    payment.setCreatedAt(trantor::Date::now());
    payment.setUpdatedAt(trantor::Date::now());
    paymentMapper.insert(payment);

    Json::Value wechatConfig;
    wechatConfig["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    wechatConfig["serial_no"] = "SERIAL_TEST";
    wechatConfig["app_id"] = "wx_app";
    wechatConfig["mch_id"] = "mch_123";
    auto wechatClient = std::make_shared<WechatPayClient>(wechatConfig);

    Json::Value notify;
    notify["id"] = "notify_" + drogon::utils::getUuid();
    notify["event_type"] = "TRANSACTION.SUCCESS";
    notify["resource_type"] = "encrypt-resource";
    notify["resource"]["algorithm"] = "AEAD_AES_256_GCM";
    notify["resource"]["ciphertext"] = "dummy";
    notify["resource"]["nonce"] = "nonce";
    notify["resource"]["associated_data"] = "transaction";
    const std::string body = toJsonCompact(notify);

    PayPlugin plugin;
    plugin.setTestClients(wechatClient, client);

    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setBody(body);

    std::promise<drogon::HttpResponsePtr> promise;
    plugin.handleWechatCallback(
        req,
        [&promise](const drogon::HttpResponsePtr &resp) {
            promise.set_value(resp);
        });

    auto future = promise.get_future();
    CHECK(future.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
    const auto resp = future.get();
    CHECK(resp != nullptr);
    CHECK(resp->statusCode() == drogon::k400BadRequest);

    const auto callbackRows = client->execSqlSync(
        "SELECT id FROM pay_callback WHERE payment_no = $1",
        paymentNo);
    CHECK(callbackRows.empty());

    const auto updatedPayment = paymentMapper.findByPrimaryKey(
        payment.getValueOfId());
    CHECK(updatedPayment.getValueOfStatus() == "PROCESSING");

    const auto updatedOrder = orderMapper.findByPrimaryKey(
        order.getValueOfId());
    CHECK(updatedOrder.getValueOfStatus() == "PAYING");

    client->execSqlSync("DELETE FROM pay_payment WHERE payment_no = $1",
                        paymentNo);
    client->execSqlSync("DELETE FROM pay_order WHERE order_no = $1", orderNo);
}
