#pragma once

#include <json/json.h>
#include <functional>
#include <string>

class WechatPayClient
{
  public:
    using JsonCallback =
        std::function<void(const Json::Value &result, const std::string &error)>;

    explicit WechatPayClient(const Json::Value &config);

    void createTransactionNative(const Json::Value &payload,
                                 JsonCallback &&callback);
    void queryTransaction(const std::string &orderNo,
                          JsonCallback &&callback);
    void refund(const Json::Value &payload, JsonCallback &&callback);
    void queryRefund(const std::string &refundNo, JsonCallback &&callback);

    std::string buildAuthorizationHeader(const std::string &method,
                                         const std::string &url,
                                         const std::string &body,
                                         const std::string &timestamp,
                                         const std::string &nonce,
                                         std::string &error) const;

    bool verifyCallback(const std::string &timestamp,
                        const std::string &nonce,
                        const std::string &body,
                        const std::string &signature,
                        const std::string &serialNo,
                        std::string &error) const;

    bool decryptResource(const std::string &ciphertext,
                         const std::string &nonce,
                         const std::string &associatedData,
                         std::string &plaintext,
                         std::string &error) const;

    const std::string &getAppId() const { return appId_; }
    const std::string &getMchId() const { return mchId_; }

  private:
    Json::Value config_;
    std::string appId_;
    std::string mchId_;
    std::string serialNo_;
    std::string apiV3Key_;
    std::string privateKeyPath_;
    std::string platformCertPath_;
    std::string apiBase_;
    std::string notifyUrl_;
};
