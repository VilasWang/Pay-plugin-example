#include <drogon/drogon_test.h>
#include "../utils/PayUtils.h"

DROGON_TEST(PayUtils_GetRequiredString)
{
    Json::Value json;
    json["user_id"] = "123";
    json["amount"] = 456;

    std::string value;
    CHECK(pay::utils::getRequiredString(json, "user_id", value));
    CHECK(value == "123");

    value.clear();
    CHECK(pay::utils::getRequiredString(json, "amount", value));
    CHECK(value == "456");

    value.clear();
    CHECK(!pay::utils::getRequiredString(json, "missing", value));
}

DROGON_TEST(PayUtils_ParseAmountToFen)
{
    int64_t fen = 0;
    CHECK(pay::utils::parseAmountToFen("12.34", fen));
    CHECK(fen == 1234);

    CHECK(pay::utils::parseAmountToFen("12", fen));
    CHECK(fen == 1200);

    CHECK(pay::utils::parseAmountToFen("0.1", fen));
    CHECK(fen == 10);

    CHECK(pay::utils::parseAmountToFen("0.01", fen));
    CHECK(fen == 1);

    CHECK(pay::utils::parseAmountToFen(".5", fen));
    CHECK(fen == 50);

    CHECK(!pay::utils::parseAmountToFen("", fen));
    CHECK(!pay::utils::parseAmountToFen("12.345", fen));
    CHECK(!pay::utils::parseAmountToFen("12.a", fen));
    CHECK(!pay::utils::parseAmountToFen("-1.00", fen));
}

DROGON_TEST(PayUtils_MapTradeState)
{
    std::string orderStatus;
    std::string paymentStatus;

    pay::utils::mapTradeState("SUCCESS", orderStatus, paymentStatus);
    CHECK(orderStatus == "PAID");
    CHECK(paymentStatus == "SUCCESS");

    pay::utils::mapTradeState("USERPAYING", orderStatus, paymentStatus);
    CHECK(orderStatus == "PAYING");
    CHECK(paymentStatus == "PROCESSING");

    pay::utils::mapTradeState("NOTPAY", orderStatus, paymentStatus);
    CHECK(orderStatus == "PAYING");
    CHECK(paymentStatus == "PROCESSING");

    pay::utils::mapTradeState("CLOSED", orderStatus, paymentStatus);
    CHECK(orderStatus == "CLOSED");
    CHECK(paymentStatus == "FAIL");

    pay::utils::mapTradeState("UNKNOWN", orderStatus, paymentStatus);
    CHECK(orderStatus == "FAILED");
    CHECK(paymentStatus == "FAIL");
}

DROGON_TEST(PayUtils_MapRefundStatus)
{
    CHECK(pay::utils::mapRefundStatus("SUCCESS") == "REFUND_SUCCESS");
    CHECK(pay::utils::mapRefundStatus("CLOSED") == "REFUND_FAIL");
    CHECK(pay::utils::mapRefundStatus("ABNORMAL") == "REFUND_FAIL");
    CHECK(pay::utils::mapRefundStatus("PROCESSING") == "REFUNDING");
    CHECK(pay::utils::mapRefundStatus("UNKNOWN") == "");
}

DROGON_TEST(PayUtils_ToJsonString)
{
    Json::Value root;
    root["order_id"] = "order_1";
    root["amount"] = 1200;

    const auto json = pay::utils::toJsonString(root);

    CHECK(json.find('\n') == std::string::npos);
    CHECK(json.find("\"order_id\"") != std::string::npos);
    CHECK(json.find("\"amount\"") != std::string::npos);
}
