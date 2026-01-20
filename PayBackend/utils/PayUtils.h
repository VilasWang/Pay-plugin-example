#pragma once
#include <cstdint>
#include <json/json.h>
#include <string>

namespace pay::utils
{
bool getRequiredString(const Json::Value &json,
                       const char *key,
                       std::string &value);

bool parseAmountToFen(const std::string &amount, int64_t &fen);

std::string toJsonString(const Json::Value &value);

void mapTradeState(const std::string &tradeState,
                   std::string &orderStatus,
                   std::string &paymentStatus);

std::string mapRefundStatus(const std::string &wechatStatus);
}
