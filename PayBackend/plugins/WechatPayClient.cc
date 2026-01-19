#include "WechatPayClient.h"
#include <drogon/HttpClient.h>
#include <drogon/utils/Utilities.h>
#include <fstream>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace
{
std::string readFile(const std::string &path, std::string &error)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        error = "failed to open file: " + path;
        return {};
    }
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    return content;
}

bool signMessage(const std::string &message,
                 const std::string &privateKeyPath,
                 std::string &signatureB64,
                 std::string &error)
{
    std::string keyError;
    std::string keyContent = readFile(privateKeyPath, keyError);
    if (!keyError.empty())
    {
        error = keyError;
        return false;
    }

    BIO *bio = BIO_new_mem_buf(keyContent.data(),
                               static_cast<int>(keyContent.size()));
    if (!bio)
    {
        error = "failed to create BIO for private key";
        return false;
    }

    EVP_PKEY *pkey =
        PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey)
    {
        error = "failed to load private key";
        return false;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(pkey);
        error = "failed to create EVP_MD_CTX";
        return false;
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        error = "EVP_DigestSignInit failed";
        return false;
    }

    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        error = "EVP_DigestSignUpdate failed";
        return false;
    }

    size_t sigLen = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        error = "EVP_DigestSignFinal size failed";
        return false;
    }

    std::string signature(sigLen, '\0');
    if (EVP_DigestSignFinal(ctx,
                            reinterpret_cast<unsigned char *>(&signature[0]),
                            &sigLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        error = "EVP_DigestSignFinal failed";
        return false;
    }

    signature.resize(sigLen);
    signatureB64 = drogon::utils::base64Encode(signature);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return true;
}

bool verifyMessage(const std::string &message,
                   const std::string &signatureB64,
                   const std::string &certPath,
                   std::string &error)
{
    std::string certError;
    std::string certContent = readFile(certPath, certError);
    if (!certError.empty())
    {
        error = certError;
        return false;
    }

    BIO *bio = BIO_new_mem_buf(certContent.data(),
                               static_cast<int>(certContent.size()));
    if (!bio)
    {
        error = "failed to create BIO for cert";
        return false;
    }

    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert)
    {
        error = "failed to load platform cert";
        return false;
    }

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    X509_free(cert);
    if (!pkey)
    {
        error = "failed to extract public key";
        return false;
    }

    auto signature = drogon::utils::base64Decode(signatureB64);
    if (signature.empty())
    {
        EVP_PKEY_free(pkey);
        error = "failed to decode signature";
        return false;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(pkey);
        error = "failed to create EVP_MD_CTX";
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        error = "EVP_DigestVerifyInit failed";
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        error = "EVP_DigestVerifyUpdate failed";
        return false;
    }

    int ok = EVP_DigestVerifyFinal(
        ctx,
        reinterpret_cast<const unsigned char *>(signature.data()),
        signature.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (ok != 1)
    {
        error = "signature verify failed";
        return false;
    }
    return true;
}

bool decryptAesGcm(const std::string &ciphertextB64,
                   const std::string &nonce,
                   const std::string &aad,
                   const std::string &apiV3Key,
                   std::string &plaintext,
                   std::string &error)
{
    if (apiV3Key.size() != 32)
    {
        error = "api_v3_key must be 32 bytes";
        return false;
    }

    auto ciphertext = drogon::utils::base64Decode(ciphertextB64);
    if (ciphertext.size() < 16)
    {
        error = "ciphertext too short";
        return false;
    }

    const size_t tagLen = 16;
    const size_t textLen = ciphertext.size() - tagLen;
    const unsigned char *tag =
        reinterpret_cast<const unsigned char *>(ciphertext.data() + textLen);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        error = "failed to create cipher ctx";
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) !=
        1)
    {
        EVP_CIPHER_CTX_free(ctx);
        error = "EVP_DecryptInit_ex failed";
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(),
                            nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        error = "set iv len failed";
        return false;
    }

    if (EVP_DecryptInit_ex(
            ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char *>(apiV3Key.data()),
            reinterpret_cast<const unsigned char *>(nonce.data())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        error = "set key/iv failed";
        return false;
    }

    int outLen = 0;
    if (!aad.empty())
    {
        if (EVP_DecryptUpdate(ctx, nullptr, &outLen,
                              reinterpret_cast<const unsigned char *>(aad.data()),
                              aad.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            error = "set aad failed";
            return false;
        }
    }

    plaintext.resize(textLen);
    if (EVP_DecryptUpdate(
            ctx,
            reinterpret_cast<unsigned char *>(&plaintext[0]),
            &outLen,
            reinterpret_cast<const unsigned char *>(ciphertext.data()),
            textLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        error = "decrypt update failed";
        return false;
    }
    int totalLen = outLen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLen,
                            const_cast<unsigned char *>(tag)) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        error = "set tag failed";
        return false;
    }

    int finalOk = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&plaintext[totalLen]), &outLen);
    EVP_CIPHER_CTX_free(ctx);
    if (finalOk != 1)
    {
        error = "decrypt final failed";
        return false;
    }
    plaintext.resize(totalLen + outLen);
    return true;
}

std::string toJsonString(const Json::Value &value)
{
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, value);
}

void sendWechatRequest(const std::string &apiBase,
                       const std::string &method,
                       const std::string &path,
                       const std::string &body,
                       const std::string &authHeader,
                       WechatPayClient::JsonCallback &&callback)
{
    auto client = drogon::HttpClient::newHttpClient(apiBase);
    auto req = drogon::HttpRequest::newHttpRequest();
    if (method == "GET")
    {
        req->setMethod(drogon::Get);
    }
    else if (method == "POST")
    {
        req->setMethod(drogon::Post);
        req->setBody(body);
    }
    else
    {
        Json::Value result;
        callback(result, "unsupported method");
        return;
    }

    req->setPath(path);
    req->addHeader("Accept", "application/json");
    req->addHeader("Content-Type", "application/json");
    req->addHeader("User-Agent", "PayPlugin/1.0");
    req->addHeader("Authorization", authHeader);

    auto cb = std::make_shared<WechatPayClient::JsonCallback>(
        std::move(callback));

    client->sendRequest(
        req, [cb](drogon::ReqResult result,
                  const drogon::HttpResponsePtr &resp) {
            Json::Value bodyJson;
            if (result != drogon::ReqResult::Ok || !resp)
            {
                (*cb)(bodyJson, "http request failed");
                return;
            }

            auto json = resp->getJsonObject();
            if (json)
            {
                (*cb)(*json, "");
                return;
            }

            Json::CharReaderBuilder builder;
            std::unique_ptr<Json::CharReader> reader(
                builder.newCharReader());
            std::string errors;
            const auto body = resp->body();
            if (!reader->parse(body.data(),
                               body.data() + body.size(),
                               &bodyJson,
                               &errors))
            {
                (*cb)(bodyJson, "invalid json response");
                return;
            }
            (*cb)(bodyJson, "");
        });
}
} // namespace

WechatPayClient::WechatPayClient(const Json::Value &config) : config_(config)
{
    appId_ = config.get("app_id", "").asString();
    mchId_ = config.get("mch_id", "").asString();
    serialNo_ = config.get("serial_no", "").asString();
    apiV3Key_ = config.get("api_v3_key", "").asString();
    privateKeyPath_ = config.get("private_key_path", "").asString();
    platformCertPath_ = config.get("platform_cert_path", "").asString();
    apiBase_ = config.get("api_base", "https://api.mch.weixin.qq.com").asString();
    notifyUrl_ = config.get("notify_url", "").asString();
}

void WechatPayClient::createTransactionNative(const Json::Value &payload,
                                              JsonCallback &&callback)
{
    Json::Value request = payload;
    if (request.get("appid", "").asString().empty())
    {
        request["appid"] = appId_;
    }
    if (request.get("mchid", "").asString().empty())
    {
        request["mchid"] = mchId_;
    }
    if (request.get("notify_url", "").asString().empty())
    {
        request["notify_url"] = notifyUrl_;
    }

    if (request.get("appid", "").asString().empty() ||
        request.get("mchid", "").asString().empty() ||
        request.get("notify_url", "").asString().empty())
    {
        Json::Value result;
        callback(result, "missing appid/mchid/notify_url");
        return;
    }

    const std::string path = "/v3/pay/transactions/native";
    const std::string body = toJsonString(request);

    const std::string timestamp = std::to_string(std::time(nullptr));
    const std::string nonce = drogon::utils::getUuid();
    std::string error;
    std::string auth = buildAuthorizationHeader(
        "POST", path, body, timestamp, nonce, error);
    if (!error.empty())
    {
        Json::Value result;
        callback(result, error);
        return;
    }

    sendWechatRequest(apiBase_, "POST", path, body, auth,
                      std::move(callback));
}

void WechatPayClient::queryTransaction(const std::string &orderNo,
                                       JsonCallback &&callback)
{
    if (orderNo.empty())
    {
        Json::Value result;
        callback(result, "missing orderNo");
        return;
    }
    if (mchId_.empty())
    {
        Json::Value result;
        callback(result, "missing mch_id");
        return;
    }

    const std::string path =
        "/v3/pay/transactions/out-trade-no/" + orderNo + "?mchid=" + mchId_;
    const std::string body;
    const std::string timestamp = std::to_string(std::time(nullptr));
    const std::string nonce = drogon::utils::getUuid();
    std::string error;
    std::string auth = buildAuthorizationHeader(
        "GET", path, body, timestamp, nonce, error);
    if (!error.empty())
    {
        Json::Value result;
        callback(result, error);
        return;
    }

    sendWechatRequest(apiBase_, "GET", path, body, auth,
                      std::move(callback));
}

void WechatPayClient::refund(const Json::Value &payload,
                             JsonCallback &&callback)
{
    Json::Value request = payload;
    if (request.get("notify_url", "").asString().empty())
    {
        request["notify_url"] = notifyUrl_;
    }

    const std::string path = "/v3/refund/domestic/refunds";
    const std::string body = toJsonString(request);
    const std::string timestamp = std::to_string(std::time(nullptr));
    const std::string nonce = drogon::utils::getUuid();
    std::string error;
    std::string auth = buildAuthorizationHeader(
        "POST", path, body, timestamp, nonce, error);
    if (!error.empty())
    {
        Json::Value result;
        callback(result, error);
        return;
    }

    sendWechatRequest(apiBase_, "POST", path, body, auth,
                      std::move(callback));
}

void WechatPayClient::queryRefund(const std::string &refundNo,
                                  JsonCallback &&callback)
{
    if (refundNo.empty())
    {
        Json::Value result;
        callback(result, "missing refundNo");
        return;
    }

    const std::string path = "/v3/refund/domestic/refunds/" + refundNo;
    const std::string body;
    const std::string timestamp = std::to_string(std::time(nullptr));
    const std::string nonce = drogon::utils::getUuid();
    std::string error;
    std::string auth = buildAuthorizationHeader(
        "GET", path, body, timestamp, nonce, error);
    if (!error.empty())
    {
        Json::Value result;
        callback(result, error);
        return;
    }

    sendWechatRequest(apiBase_, "GET", path, body, auth,
                      std::move(callback));
}

std::string WechatPayClient::buildAuthorizationHeader(
    const std::string &method,
    const std::string &url,
    const std::string &body,
    const std::string &timestamp,
    const std::string &nonce,
    std::string &error) const
{
    if (mchId_.empty() || serialNo_.empty() || privateKeyPath_.empty())
    {
        error = "wechat pay config missing mch_id/serial_no/private_key_path";
        return {};
    }

    std::string message = method + "\n" + url + "\n" + timestamp + "\n" + nonce +
                          "\n" + body + "\n";
    std::string signatureB64;
    if (!signMessage(message, privateKeyPath_, signatureB64, error))
    {
        return {};
    }

    std::string auth =
        "WECHATPAY2-SHA256-RSA2048 mchid=\"" + mchId_ + "\","
        "nonce_str=\"" + nonce + "\","
        "timestamp=\"" + timestamp + "\","
        "serial_no=\"" + serialNo_ + "\","
        "signature=\"" + signatureB64 + "\"";
    return auth;
}

bool WechatPayClient::verifyCallback(const std::string &timestamp,
                                     const std::string &nonce,
                                     const std::string &body,
                                     const std::string &signature,
                                     const std::string &serialNo,
                                     std::string &error) const
{
    if (platformCertPath_.empty())
    {
        error = "platform_cert_path is not configured";
        return false;
    }
    if (!serialNo_.empty() && serialNo_ != serialNo)
    {
        error = "serial number mismatch";
        return false;
    }

    std::string message =
        timestamp + "\n" + nonce + "\n" + body + "\n";
    return verifyMessage(message, signature, platformCertPath_, error);
}

bool WechatPayClient::decryptResource(const std::string &ciphertext,
                                      const std::string &nonce,
                                      const std::string &associatedData,
                                      std::string &plaintext,
                                      std::string &error) const
{
    if (apiV3Key_.empty())
    {
        error = "api_v3_key is not configured";
        return false;
    }

    return decryptAesGcm(ciphertext, nonce, associatedData, apiV3Key_, plaintext,
                         error);
}
