#include <drogon/drogon.h>
#include <string>

using namespace drogon;

void setupCors()
{
    auto isAllowed = [](const std::string &origin) -> bool {
        if (origin.empty())
            return false;

        const auto &customConfig = drogon::app().getCustomConfig();
        const auto &allowOrigins = customConfig["cors"]["allow_origins"];

        if (allowOrigins.isArray())
        {
            for (const auto &allowed : allowOrigins)
            {
                if (allowed.asString() == origin)
                    return true;
            }
        }
        return false;
    };

    drogon::app().registerSyncAdvice(
        [isAllowed](
            const drogon::HttpRequestPtr &req) -> drogon::HttpResponsePtr {
            if (req->method() == drogon::HttpMethod::Options)
            {
                const auto &origin = req->getHeader("Origin");
                if (isAllowed(origin))
                {
                    auto resp = drogon::HttpResponse::newHttpResponse();
                    resp->addHeader("Access-Control-Allow-Origin", origin);

                    const auto &requestMethod =
                        req->getHeader("Access-Control-Request-Method");
                    if (!requestMethod.empty())
                    {
                        resp->addHeader("Access-Control-Allow-Methods",
                                        requestMethod);
                    }

                    resp->addHeader("Access-Control-Allow-Credentials", "true");

                    const auto &requestHeaders =
                        req->getHeader("Access-Control-Request-Headers");
                    if (!requestHeaders.empty())
                    {
                        resp->addHeader("Access-Control-Allow-Headers",
                                        requestHeaders);
                    }
                    return resp;
                }
            }
            return {};
        });

    drogon::app().registerPostHandlingAdvice(
        [isAllowed](const drogon::HttpRequestPtr &req,
                    const drogon::HttpResponsePtr &resp) {
            const auto &origin = req->getHeader("Origin");
            if (isAllowed(origin))
            {
                resp->addHeader("Access-Control-Allow-Origin", origin);
                resp->addHeader("Access-Control-Allow-Methods",
                                "GET, POST, OPTIONS");
                resp->addHeader("Access-Control-Allow-Headers",
                                "Content-Type, Authorization");
                resp->addHeader("Access-Control-Allow-Credentials", "true");
            }
        });
}

int main()
{
    drogon::app().loadConfigFile("./config.json");
    setupCors();
    drogon::app().run();
    return 0;
}
