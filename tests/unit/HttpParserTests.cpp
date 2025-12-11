#include "http/HttpParser.hpp"

#include <gtest/gtest.h>
#include <string>

using namespace http_server::http;

TEST(HttpParserTest, ParseSimpleGetRequest) {
    HttpParser parser;
    const char* request = "GET /info HTTP/1.1\r\nHost: localhost\r\n\r\n";

    auto result = parser.Feed(request, strlen(request));
    EXPECT_EQ(result, ParseResult::Complete);

    const auto& req = parser.GetRequest();
    EXPECT_EQ(req.GetMethod(), HttpMethod::GET);
    EXPECT_EQ(req.GetPath(), "/info");
    EXPECT_EQ(req.GetHttpVersion(), "HTTP/1.1");
}

TEST(HttpParserTest, ParseGetRequestWithQueryString) {
    HttpParser parser;
    const char* request = "GET /data?key=value&foo=bar HTTP/1.1\r\nHost: localhost\r\n\r\n";

    auto result = parser.Feed(request, strlen(request));
    EXPECT_EQ(result, ParseResult::Complete);

    const auto& req = parser.GetRequest();
    EXPECT_EQ(req.GetPath(), "/data");

    auto key = req.GetQueryParam("key");
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(*key, "value");

    auto foo = req.GetQueryParam("foo");
    ASSERT_TRUE(foo.has_value());
    EXPECT_EQ(*foo, "bar");
}

TEST(HttpParserTest, ParsePostRequestWithBody) {
    HttpParser parser;
    std::string request =
        "POST /data HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 16\r\n"
        "\r\n"
        "{\"name\": \"test\"}";

    auto result = parser.Feed(request);
    EXPECT_EQ(result, ParseResult::Complete);

    const auto& req = parser.GetRequest();
    EXPECT_EQ(req.GetMethod(), HttpMethod::POST);
    EXPECT_EQ(req.GetPath(), "/data");
    EXPECT_EQ(req.GetBody(), "{\"name\": \"test\"}");
}

TEST(HttpParserTest, ParseIncrementalData) {
    HttpParser parser;

    // Send request in parts
    auto result = parser.Feed("GET /info HTTP/1.1\r\n");
    EXPECT_EQ(result, ParseResult::NeedMoreData);

    result = parser.Feed("Host: localhost\r\n");
    EXPECT_EQ(result, ParseResult::NeedMoreData);

    result = parser.Feed("\r\n");
    EXPECT_EQ(result, ParseResult::Complete);

    EXPECT_TRUE(parser.IsComplete());
}

TEST(HttpParserTest, ParseHeaders) {
    HttpParser parser;
    std::string request =
        "GET /info HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "User-Agent: TestClient/1.0\r\n"
        "Accept: application/json\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";

    auto result = parser.Feed(request);
    EXPECT_EQ(result, ParseResult::Complete);

    const auto& req = parser.GetRequest();
    auto host = req.GetHeader("host");
    ASSERT_TRUE(host.has_value());
    EXPECT_EQ(*host, "localhost:8080");

    auto userAgent = req.GetHeader("user-agent");
    ASSERT_TRUE(userAgent.has_value());
    EXPECT_EQ(*userAgent, "TestClient/1.0");

    EXPECT_TRUE(req.IsKeepAlive());
}

TEST(HttpParserTest, RejectMalformedRequestLine) {
    HttpParser parser;
    const char* request = "INVALID REQUEST LINE\r\n\r\n";

    auto result = parser.Feed(request, strlen(request));
    EXPECT_EQ(result, ParseResult::MalformedRequest);
    EXPECT_TRUE(parser.HasError());
}

TEST(HttpParserTest, RejectUnsupportedMethod) {
    HttpParser parser;
    const char* request = "PUT /data HTTP/1.1\r\nHost: localhost\r\n\r\n";

    auto result = parser.Feed(request, strlen(request));
    EXPECT_EQ(result, ParseResult::UnsupportedMethod);
}

TEST(HttpParserTest, RejectPathTraversal) {
    HttpParser parser;
    const char* request = "GET /../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n";

    auto result = parser.Feed(request, strlen(request));
    EXPECT_EQ(result, ParseResult::MalformedRequest);
}

TEST(HttpParserTest, ParserReset) {
    HttpParser parser;
    const char* request1 = "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n";

    auto result = parser.Feed(request1, strlen(request1));
    EXPECT_EQ(result, ParseResult::Complete);
    EXPECT_EQ(parser.GetRequest().GetPath(), "/first");

    parser.Reset();

    const char* request2 = "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n";
    result = parser.Feed(request2, strlen(request2));
    EXPECT_EQ(result, ParseResult::Complete);
    EXPECT_EQ(parser.GetRequest().GetPath(), "/second");
}

TEST(HttpParserTest, ConnectionClose) {
    HttpParser parser;
    std::string request =
        "GET /info HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "\r\n";

    auto result = parser.Feed(request);
    EXPECT_EQ(result, ParseResult::Complete);
    EXPECT_FALSE(parser.GetRequest().IsKeepAlive());
}
