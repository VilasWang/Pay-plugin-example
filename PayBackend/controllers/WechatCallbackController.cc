#include "WechatCallbackController.h"

void WechatCallbackController::notify(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback)
{
    auto plugin = drogon::app().getPlugin<PayPlugin>();
    plugin->handleWechatCallback(req, std::move(callback));
}
