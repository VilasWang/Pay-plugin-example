#include "PayUtils.h"
#include <cctype>

namespace pay::utils
{
bool getRequiredString(const Json::Value &json,
                       const char *key,
                       std::string &value)
{
    if (!json.isMember(key))
    {
        return false;
    }
    if (json[key].isString())
    {
        value = json[key].asString();
        return !value.empty();
    }
    if (json[key].isNumeric())
    {
        value = json[key].asString();
        return !value.empty();
    }
    return false;
}

bool parseAmountToFen(const std::string &amount, int64_t &fen)
{
    if (amount.empty())
    {
        return false;
    }

    std::string yuanPart;
    std::string centPart;
    const auto dotPos = amount.find('.');
    if (dotPos == std::string::npos)
    {
        yuanPart = amount;
        centPart = "00";
    }
    else
    {
        yuanPart = amount.substr(0, dotPos);
        centPart = amount.substr(dotPos + 1);
    }

    if (yuanPart.empty())
    {
        yuanPart = "0";
    }

    for (char c : yuanPart)
    {
        if (!std::isdigit(static_cast<unsigned char>(c)))
        {
            return false;
        }
    }
    for (char c : centPart)
    {
        if (!std::isdigit(static_cast<unsigned char>(c)))
        {
            return false;
        }
    }

    if (centPart.size() > 2)
    {
        return false;
    }
    if (centPart.size() == 1)
    {
        centPart.push_back('0');
    }
    if (centPart.empty())
    {
        centPart = "00";
    }

    try
    {
        const int64_t yuan = std::stoll(yuanPart);
        const int64_t cents = std::stoll(centPart);
        fen = yuan * 100 + cents;
        return true;
    }
    catch (...)
    {
        return false;
    }
}

std::string toJsonString(const Json::Value &value)
{
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, value);
}

void mapTradeState(const std::string &tradeState,
                   std::string &orderStatus,
                   std::string &paymentStatus)
{
    orderStatus = "FAILED";
    paymentStatus = "FAIL";
    if (tradeState == "SUCCESS")
    {
        orderStatus = "PAID";
        paymentStatus = "SUCCESS";
    }
    else if (tradeState == "USERPAYING" || tradeState == "NOTPAY")
    {
        orderStatus = "PAYING";
        paymentStatus = "PROCESSING";
    }
    else if (tradeState == "CLOSED" || tradeState == "REVOKED" ||
             tradeState == "REFUND")
    {
        orderStatus = "CLOSED";
        paymentStatus = "FAIL";
    }
}

std::string mapRefundStatus(const std::string &wechatStatus)
{
    if (wechatStatus == "SUCCESS")
    {
        return "REFUND_SUCCESS";
    }
    if (wechatStatus == "CLOSED")
    {
        return "REFUND_FAIL";
    }
    if (wechatStatus == "ABNORMAL")
    {
        return "REFUND_FAIL";
    }
    return "REFUNDING";
}
}  // namespace pay::utils
