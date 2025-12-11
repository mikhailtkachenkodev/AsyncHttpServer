#include "http/HttpRequest.hpp"

#include <gtest/gtest.h>
#include <string>

using namespace http_server::http;

class HttpRequestTest : public ::testing::Test {
protected:
    HttpRequest request;
};

TEST_F(HttpRequestTest, DefaultConstruction) {
    EXPECT_EQ(request.GetMethod(), HttpMethod::UNKNOWN);
    EXPECT_TRUE(request.GetPath().empty());
    EXPECT_TRUE(request.GetHttpVersion().empty());
    EXPECT_TRUE(request.GetBody().empty());
}

TEST_F(HttpRequestTest, SetAndGetMethod) {
    request.SetMethod(HttpMethod::GET);
    EXPECT_EQ(request.GetMethod(), HttpMethod::GET);

    request.SetMethod(HttpMethod::POST);
    EXPECT_EQ(request.GetMethod(), HttpMethod::POST);
}

TEST_F(HttpRequestTest, SetPathWithoutQueryString) {
    request.SetPath("/info");
    EXPECT_EQ(request.GetPath(), "/info");
    EXPECT_TRUE(request.GetQueryString().empty());
    EXPECT_TRUE(request.GetQueryParams().empty());
}

TEST_F(HttpRequestTest, SetPathWithQueryString) {
    request.SetPath("/data?key=value&foo=bar");
    EXPECT_EQ(request.GetPath(), "/data");
    EXPECT_EQ(request.GetQueryString(), "key=value&foo=bar");

    auto key = request.GetQueryParam("key");
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(*key, "value");

    auto foo = request.GetQueryParam("foo");
    ASSERT_TRUE(foo.has_value());
    EXPECT_EQ(*foo, "bar");
}

TEST_F(HttpRequestTest, QueryParamUrlDecoding) {
    request.SetPath("/search?q=hello%20world&name=test%2Bvalue");

    auto q = request.GetQueryParam("q");
    ASSERT_TRUE(q.has_value());
    EXPECT_EQ(*q, "hello world");

    auto name = request.GetQueryParam("name");
    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(*name, "test+value");
}

TEST_F(HttpRequestTest, QueryParamPlusAsSpace) {
    request.SetPath("/search?q=hello+world");

    auto q = request.GetQueryParam("q");
    ASSERT_TRUE(q.has_value());
    EXPECT_EQ(*q, "hello world");
}

TEST_F(HttpRequestTest, QueryParamWithoutValue) {
    request.SetPath("/data?flag&key=value");

    auto flag = request.GetQueryParam("flag");
    ASSERT_TRUE(flag.has_value());
    EXPECT_EQ(*flag, "");

    auto key = request.GetQueryParam("key");
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(*key, "value");
}

TEST_F(HttpRequestTest, GetNonExistentQueryParam) {
    request.SetPath("/data?key=value");
    auto missing = request.GetQueryParam("missing");
    EXPECT_FALSE(missing.has_value());
}

TEST_F(HttpRequestTest, AddAndGetHeaders) {
    request.AddHeader("Content-Type", "application/json");
    request.AddHeader("Accept", "text/html");

    auto contentType = request.GetHeader("Content-Type");
    ASSERT_TRUE(contentType.has_value());
    EXPECT_EQ(*contentType, "application/json");

    auto accept = request.GetHeader("Accept");
    ASSERT_TRUE(accept.has_value());
    EXPECT_EQ(*accept, "text/html");
}

TEST_F(HttpRequestTest, HeadersCaseInsensitive) {
    request.AddHeader("Content-Type", "application/json");

    auto lower = request.GetHeader("content-type");
    ASSERT_TRUE(lower.has_value());
    EXPECT_EQ(*lower, "application/json");

    auto upper = request.GetHeader("CONTENT-TYPE");
    ASSERT_TRUE(upper.has_value());
    EXPECT_EQ(*upper, "application/json");

    auto mixed = request.GetHeader("Content-TYPE");
    ASSERT_TRUE(mixed.has_value());
    EXPECT_EQ(*mixed, "application/json");
}

TEST_F(HttpRequestTest, HasHeader) {
    request.AddHeader("Host", "localhost");

    EXPECT_TRUE(request.HasHeader("Host"));
    EXPECT_TRUE(request.HasHeader("host"));
    EXPECT_FALSE(request.HasHeader("Content-Type"));
}

TEST_F(HttpRequestTest, GetNonExistentHeader) {
    auto missing = request.GetHeader("X-Custom-Header");
    EXPECT_FALSE(missing.has_value());
}

TEST_F(HttpRequestTest, SetAndGetPathParams) {
    request.SetPathParam("id", "123");
    request.SetPathParam("name", "test");

    auto id = request.GetPathParam("id");
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, "123");

    auto name = request.GetPathParam("name");
    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(*name, "test");
}

TEST_F(HttpRequestTest, GetNonExistentPathParam) {
    auto missing = request.GetPathParam("missing");
    EXPECT_FALSE(missing.has_value());
}

TEST_F(HttpRequestTest, SetAndGetBody) {
    std::string body = "{\"key\": \"value\"}";
    request.SetBody(body);
    EXPECT_EQ(request.GetBody(), body);
}

TEST_F(HttpRequestTest, SetBodyWithMove) {
    std::string body = "{\"key\": \"value\"}";
    std::string expected = body;
    request.SetBody(std::move(body));
    EXPECT_EQ(request.GetBody(), expected);
}

TEST_F(HttpRequestTest, GetContentLength) {
    request.AddHeader("Content-Length", "100");
    EXPECT_EQ(request.GetContentLength(), 100);
}

TEST_F(HttpRequestTest, GetContentLengthMissing) {
    EXPECT_EQ(request.GetContentLength(), 0);
}

TEST_F(HttpRequestTest, GetContentLengthInvalid) {
    request.AddHeader("Content-Length", "invalid");
    EXPECT_EQ(request.GetContentLength(), 0);
}

TEST_F(HttpRequestTest, GetContentType) {
    request.AddHeader("Content-Type", "application/json");
    EXPECT_EQ(request.GetContentType(), "application/json");
}

TEST_F(HttpRequestTest, GetContentTypeMissing) {
    EXPECT_EQ(request.GetContentType(), "");
}

TEST_F(HttpRequestTest, IsKeepAliveHttp11Default) {
    request.SetHttpVersion("HTTP/1.1");
    EXPECT_TRUE(request.IsKeepAlive());
}

TEST_F(HttpRequestTest, IsKeepAliveHttp10Default) {
    request.SetHttpVersion("HTTP/1.0");
    EXPECT_FALSE(request.IsKeepAlive());
}

TEST_F(HttpRequestTest, IsKeepAliveWithCloseHeader) {
    request.SetHttpVersion("HTTP/1.1");
    request.AddHeader("Connection", "close");
    EXPECT_FALSE(request.IsKeepAlive());
}

TEST_F(HttpRequestTest, IsKeepAliveWithKeepAliveHeader) {
    request.SetHttpVersion("HTTP/1.0");
    request.AddHeader("Connection", "keep-alive");
    EXPECT_TRUE(request.IsKeepAlive());
}

TEST_F(HttpRequestTest, IsKeepAliveConnectionCaseInsensitive) {
    request.SetHttpVersion("HTTP/1.1");
    request.AddHeader("Connection", "CLOSE");
    EXPECT_FALSE(request.IsKeepAlive());
}

TEST_F(HttpRequestTest, Clear) {
    request.SetMethod(HttpMethod::POST);
    request.SetPath("/data?key=value");
    request.SetHttpVersion("HTTP/1.1");
    request.SetBody("test body");
    request.AddHeader("Content-Type", "text/plain");
    request.SetPathParam("id", "123");

    request.Clear();

    EXPECT_EQ(request.GetMethod(), HttpMethod::UNKNOWN);
    EXPECT_TRUE(request.GetPath().empty());
    EXPECT_TRUE(request.GetQueryString().empty());
    EXPECT_TRUE(request.GetHttpVersion().empty());
    EXPECT_TRUE(request.GetBody().empty());
    EXPECT_TRUE(request.GetHeaders().empty());
    EXPECT_TRUE(request.GetPathParams().empty());
    EXPECT_TRUE(request.GetQueryParams().empty());
}

TEST_F(HttpRequestTest, SetPathOverwritesPreviousQueryParams) {
    request.SetPath("/old?foo=bar");
    EXPECT_TRUE(request.GetQueryParam("foo").has_value());

    request.SetPath("/new?baz=qux");
    EXPECT_FALSE(request.GetQueryParam("foo").has_value());
    EXPECT_TRUE(request.GetQueryParam("baz").has_value());
}

TEST_F(HttpRequestTest, SetQueryParam) {
    request.SetQueryParam("key", "value");
    auto result = request.GetQueryParam("key");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "value");
}

TEST_F(HttpRequestTest, GetAllHeaders) {
    request.AddHeader("Host", "localhost");
    request.AddHeader("Accept", "*/*");

    const auto& headers = request.GetHeaders();
    EXPECT_EQ(headers.size(), 2);
}

TEST_F(HttpRequestTest, GetAllPathParams) {
    request.SetPathParam("id", "1");
    request.SetPathParam("name", "test");

    const auto& params = request.GetPathParams();
    EXPECT_EQ(params.size(), 2);
}

TEST_F(HttpRequestTest, GetAllQueryParams) {
    request.SetPath("/search?a=1&b=2&c=3");

    const auto& params = request.GetQueryParams();
    EXPECT_EQ(params.size(), 3);
}
