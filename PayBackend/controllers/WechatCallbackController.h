#pragma once

#include <drogon/HttpController.h>
#include "../plugins/PayPlugin.h"

using namespace drogon;

class WechatCallbackController
    : public drogon::HttpController<WechatCallbackController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(WechatCallbackController::notify, "/pay/notify/wechat", Post);
    METHOD_LIST_END

    void notify(const HttpRequestPtr &req,
                std::function<void(const HttpResponsePtr &)> &&callback);
};
