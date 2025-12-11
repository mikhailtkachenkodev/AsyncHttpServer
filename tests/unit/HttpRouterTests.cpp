#include "http/HttpRouter.hpp"
#include "http/HttpRequest.hpp"
#include "http/HttpResponse.hpp"

#include <gtest/gtest.h>
#include <string>

using namespace http_server::http;

TEST(HttpRouterTest, MatchStaticRoute) {
    HttpRouter router;
    bool handlerCalled = false;

    router.Get("/info", [&](HttpRequest&) {
        handlerCalled = true;
        return HttpResponse::Ok();
    });

    HttpRequest request;
    request.SetMethod(HttpMethod::GET);
    request.SetPath("/info");

    auto response = router.Route(request);
    EXPECT_TRUE(handlerCalled);
    EXPECT_EQ(response.GetStatus(), HttpStatus::OK);
}

TEST(HttpRouterTest, MatchParameterizedRoute) {
    HttpRouter router;
    std::string capturedKey;

    router.Get("/data/:key", [&](HttpRequest& req) {
        auto key = req.GetPathParam("key");
        if (key) capturedKey = *key;
        return HttpResponse::Ok();
    });

    HttpRequest request;
    request.SetMethod(HttpMethod::GET);
    request.SetPath("/data/mykey");

    auto response = router.Route(request);
    EXPECT_EQ(response.GetStatus(), HttpStatus::OK);
    EXPECT_EQ(capturedKey, "mykey");
}

TEST(HttpRouterTest, Return404ForUnknownRoute) {
    HttpRouter router;

    router.Get("/info", [](HttpRequest&) {
        return HttpResponse::Ok();
    });

    HttpRequest request;
    request.SetMethod(HttpMethod::GET);
    request.SetPath("/unknown");

    auto response = router.Route(request);
    EXPECT_EQ(response.GetStatus(), HttpStatus::NotFound);
}

TEST(HttpRouterTest, MatchCorrectMethod) {
    HttpRouter router;
    bool getHandlerCalled = false;
    bool postHandlerCalled = false;

    router.Get("/data", [&](HttpRequest&) {
        getHandlerCalled = true;
        return HttpResponse::Ok();
    });

    router.Post("/data", [&](HttpRequest&) {
        postHandlerCalled = true;
        return HttpResponse::Created();
    });

    // Test GET
    HttpRequest getRequest;
    getRequest.SetMethod(HttpMethod::GET);
    getRequest.SetPath("/data");

    auto getResponse = router.Route(getRequest);
    EXPECT_TRUE(getHandlerCalled);
    EXPECT_FALSE(postHandlerCalled);
    EXPECT_EQ(getResponse.GetStatus(), HttpStatus::OK);

    // Reset flags
    getHandlerCalled = false;

    // Test POST
    HttpRequest postRequest;
    postRequest.SetMethod(HttpMethod::POST);
    postRequest.SetPath("/data");

    auto postResponse = router.Route(postRequest);
    EXPECT_FALSE(getHandlerCalled);
    EXPECT_TRUE(postHandlerCalled);
    EXPECT_EQ(postResponse.GetStatus(), HttpStatus::Created);
}

TEST(HttpRouterTest, Return405ForWrongMethod) {
    HttpRouter router;

    router.Get("/data", [](HttpRequest&) {
        return HttpResponse::Ok();
    });

    HttpRequest request;
    request.SetMethod(HttpMethod::POST);
    request.SetPath("/data");

    auto response = router.Route(request);
    EXPECT_EQ(response.GetStatus(), HttpStatus::MethodNotAllowed);
}

TEST(HttpRouterTest, MultiplePathParameters) {
    HttpRouter router;
    std::string userId, postId;

    router.Get("/users/:userId/posts/:postId", [&](HttpRequest& req) {
        auto u = req.GetPathParam("userId");
        auto p = req.GetPathParam("postId");
        if (u) userId = *u;
        if (p) postId = *p;
        return HttpResponse::Ok();
    });

    HttpRequest request;
    request.SetMethod(HttpMethod::GET);
    request.SetPath("/users/123/posts/456");

    auto response = router.Route(request);
    EXPECT_EQ(response.GetStatus(), HttpStatus::OK);
    EXPECT_EQ(userId, "123");
    EXPECT_EQ(postId, "456");
}

TEST(HttpRouterTest, ExceptionInHandler) {
    HttpRouter router;

    router.Get("/error", [](HttpRequest&) -> HttpResponse {
        throw std::runtime_error("Test error");
    });

    HttpRequest request;
    request.SetMethod(HttpMethod::GET);
    request.SetPath("/error");

    auto response = router.Route(request);
    EXPECT_EQ(response.GetStatus(), HttpStatus::InternalServerError);
}

TEST(HttpRouterTest, CustomNotFoundHandler) {
    HttpRouter router;

    router.SetNotFoundHandler([](HttpRequest&) {
        HttpResponse response(HttpStatus::NotFound);
        response.SetJsonBody({{"custom", "not found"}});
        return response;
    });

    HttpRequest request;
    request.SetMethod(HttpMethod::GET);
    request.SetPath("/nonexistent");

    auto response = router.Route(request);
    EXPECT_EQ(response.GetStatus(), HttpStatus::NotFound);
    EXPECT_TRUE(response.GetBody().find("custom") != std::string::npos);
}
