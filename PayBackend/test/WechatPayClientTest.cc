#include <drogon/drogon_test.h>
#include "../plugins/WechatPayClient.h"
#include <drogon/utils/Utilities.h>
#include <openssl/evp.h>

namespace
{
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
}  // namespace

DROGON_TEST(WechatPayClient_DecryptResource)
{
    Json::Value config;
    config["api_v3_key"] = "0123456789abcdef0123456789abcdef";
    WechatPayClient client(config);

    const std::string plaintext = R"({"foo":"bar","amount":100})";
    const std::string nonce = "abc123nonce";
    const std::string aad = "transaction";

    const std::string ciphertextB64 =
        encryptAesGcm(plaintext, nonce, aad, config["api_v3_key"].asString());
    CHECK(!ciphertextB64.empty());

    std::string decrypted;
    std::string error;
    CHECK(client.decryptResource(ciphertextB64, nonce, aad, decrypted, error));
    CHECK(error.empty());
    CHECK(decrypted == plaintext);
}
