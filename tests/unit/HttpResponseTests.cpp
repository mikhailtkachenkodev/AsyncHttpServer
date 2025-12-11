#include "http/HttpResponse.hpp"

#include <gtest/gtest.h>
#include <string>

using namespace http_server::http;

class HttpResponseTest : public ::testing::Test {
protected:
    HttpResponse response;
};

TEST_F(HttpResponseTest, DefaultConstruction) {
    EXPECT_EQ(response.GetStatus(), HttpStatus::OK);
    EXPECT_EQ(response.GetHeader("Server"), "AsyncHttpServer/1.0");
}

TEST_F(HttpResponseTest, ConstructWithStatus) {
    HttpResponse resp(HttpStatus::NotFound);
    EXPECT_EQ(resp.GetStatus(), HttpStatus::NotFound);
}

TEST_F(HttpResponseTest, SetStatus) {
    response.SetStatus(HttpStatus::Created);
    EXPECT_EQ(response.GetStatus(), HttpStatus::Created);
}

TEST_F(HttpResponseTest, SetAndGetHeader) {
    response.SetHeader("X-Custom", "test-value");
    EXPECT_EQ(response.GetHeader("X-Custom"), "test-value");
}

TEST_F(HttpResponseTest, GetNonExistentHeader) {
    EXPECT_EQ(response.GetHeader("Missing"), "");
}

TEST_F(HttpResponseTest, RemoveHeader) {
    response.SetHeader("X-Custom", "value");
    EXPECT_EQ(response.GetHeader("X-Custom"), "value");

    response.RemoveHeader("X-Custom");
    EXPECT_EQ(response.GetHeader("X-Custom"), "");
}

TEST_F(HttpResponseTest, SetBody) {
    response.SetBody("Hello, World!");
    EXPECT_EQ(response.GetBody(), "Hello, World!");
    EXPECT_EQ(response.GetHeader("Content-Length"), "13");
}

TEST_F(HttpResponseTest, SetBodyWithMove) {
    std::string body = "Test body content";
    size_t expectedSize = body.size();
    response.SetBody(std::move(body));
    EXPECT_EQ(response.GetBody(), "Test body content");
    EXPECT_EQ(response.GetHeader("Content-Length"), std::to_string(expectedSize));
}

TEST_F(HttpResponseTest, SetJsonBody) {
    nlohmann::json data = {{"key", "value"}, {"number", 42}};
    response.SetJsonBody(data);

    EXPECT_EQ(response.GetHeader("Content-Type"), "application/json");
    EXPECT_FALSE(response.GetBody().empty());

    auto parsed = nlohmann::json::parse(response.GetBody());
    EXPECT_EQ(parsed["key"], "value");
    EXPECT_EQ(parsed["number"], 42);
}

TEST_F(HttpResponseTest, SetTextBody) {
    response.SetTextBody("Plain text content");
    EXPECT_EQ(response.GetHeader("Content-Type"), "text/plain; charset=utf-8");
    EXPECT_EQ(response.GetBody(), "Plain text content");
}

TEST_F(HttpResponseTest, SetHtmlBody) {
    response.SetHtmlBody("<html><body>Hello</body></html>");
    EXPECT_EQ(response.GetHeader("Content-Type"), "text/html; charset=utf-8");
    EXPECT_EQ(response.GetBody(), "<html><body>Hello</body></html>");
}

TEST_F(HttpResponseTest, SetContentType) {
    response.SetContentType("application/xml");
    EXPECT_EQ(response.GetHeader("Content-Type"), "application/xml");
}

TEST_F(HttpResponseTest, SetKeepAliveTrue) {
    response.SetKeepAlive(true);
    EXPECT_EQ(response.GetHeader("Connection"), "keep-alive");
}

TEST_F(HttpResponseTest, SetKeepAliveFalse) {
    response.SetKeepAlive(false);
    EXPECT_EQ(response.GetHeader("Connection"), "close");
}

TEST_F(HttpResponseTest, SerializeBasicResponse) {
    response.SetStatus(HttpStatus::OK);
    response.SetBody("test");

    std::string serialized = response.Serialize();

    EXPECT_NE(serialized.find("HTTP/1.1 200 OK\r\n"), std::string::npos);
    EXPECT_NE(serialized.find("Content-Length: 4\r\n"), std::string::npos);
    EXPECT_NE(serialized.find("\r\n\r\ntest"), std::string::npos);
}

TEST_F(HttpResponseTest, SerializeWithHeaders) {
    response.SetHeader("X-Custom", "value");
    response.SetBody("");

    std::string serialized = response.Serialize();

    EXPECT_NE(serialized.find("X-Custom: value\r\n"), std::string::npos);
}

TEST_F(HttpResponseTest, SerializeEmptyBodyHasContentLength) {
    response.SetBody("");
    std::string serialized = response.Serialize();

    EXPECT_NE(serialized.find("Content-Length: 0"), std::string::npos);
}

TEST_F(HttpResponseTest, FactoryOk) {
    auto resp = HttpResponse::Ok();
    EXPECT_EQ(resp.GetStatus(), HttpStatus::OK);
}

TEST_F(HttpResponseTest, FactoryCreated) {
    auto resp = HttpResponse::Created();
    EXPECT_EQ(resp.GetStatus(), HttpStatus::Created);
}

TEST_F(HttpResponseTest, FactoryNoContent) {
    auto resp = HttpResponse::NoContent();
    EXPECT_EQ(resp.GetStatus(), HttpStatus::NoContent);
}

TEST_F(HttpResponseTest, FactoryBadRequestWithMessage) {
    auto resp = HttpResponse::BadRequest("Invalid input");
    EXPECT_EQ(resp.GetStatus(), HttpStatus::BadRequest);

    auto parsed = nlohmann::json::parse(resp.GetBody());
    EXPECT_EQ(parsed["error"], "Invalid input");
}

TEST_F(HttpResponseTest, FactoryBadRequestWithoutMessage) {
    auto resp = HttpResponse::BadRequest();
    EXPECT_EQ(resp.GetStatus(), HttpStatus::BadRequest);
    EXPECT_TRUE(resp.GetBody().empty());
}

TEST_F(HttpResponseTest, FactoryNotFoundWithMessage) {
    auto resp = HttpResponse::NotFound("Item not found");
    EXPECT_EQ(resp.GetStatus(), HttpStatus::NotFound);

    auto parsed = nlohmann::json::parse(resp.GetBody());
    EXPECT_EQ(parsed["error"], "Item not found");
}

TEST_F(HttpResponseTest, FactoryNotFoundDefaultMessage) {
    auto resp = HttpResponse::NotFound();
    EXPECT_EQ(resp.GetStatus(), HttpStatus::NotFound);

    auto parsed = nlohmann::json::parse(resp.GetBody());
    EXPECT_EQ(parsed["error"], "Resource not found");
}

TEST_F(HttpResponseTest, FactoryMethodNotAllowed) {
    auto resp = HttpResponse::MethodNotAllowed();
    EXPECT_EQ(resp.GetStatus(), HttpStatus::MethodNotAllowed);

    auto parsed = nlohmann::json::parse(resp.GetBody());
    EXPECT_EQ(parsed["error"], "Method not allowed");
}

TEST_F(HttpResponseTest, FactoryInternalServerErrorWithMessage) {
    auto resp = HttpResponse::InternalServerError("Database failure");
    EXPECT_EQ(resp.GetStatus(), HttpStatus::InternalServerError);

    auto parsed = nlohmann::json::parse(resp.GetBody());
    EXPECT_EQ(parsed["error"], "Database failure");
}

TEST_F(HttpResponseTest, FactoryInternalServerErrorDefaultMessage) {
    auto resp = HttpResponse::InternalServerError();
    EXPECT_EQ(resp.GetStatus(), HttpStatus::InternalServerError);

    auto parsed = nlohmann::json::parse(resp.GetBody());
    EXPECT_EQ(parsed["error"], "Internal server error");
}

TEST_F(HttpResponseTest, FactoryJsonWithDefaultStatus) {
    nlohmann::json data = {{"result", "success"}};
    auto resp = HttpResponse::Json(data);

    EXPECT_EQ(resp.GetStatus(), HttpStatus::OK);
    EXPECT_EQ(resp.GetHeader("Content-Type"), "application/json");

    auto parsed = nlohmann::json::parse(resp.GetBody());
    EXPECT_EQ(parsed["result"], "success");
}

TEST_F(HttpResponseTest, FactoryJsonWithCustomStatus) {
    nlohmann::json data = {{"id", 123}};
    auto resp = HttpResponse::Json(data, HttpStatus::Created);

    EXPECT_EQ(resp.GetStatus(), HttpStatus::Created);

    auto parsed = nlohmann::json::parse(resp.GetBody());
    EXPECT_EQ(parsed["id"], 123);
}

TEST_F(HttpResponseTest, GetAllHeaders) {
    response.SetHeader("X-One", "1");
    response.SetHeader("X-Two", "2");

    const auto& headers = response.GetHeaders();
    EXPECT_GE(headers.size(), 2);
    EXPECT_EQ(headers.at("X-One"), "1");
    EXPECT_EQ(headers.at("X-Two"), "2");
}

TEST_F(HttpResponseTest, HeaderOverwrite) {
    response.SetHeader("X-Test", "first");
    response.SetHeader("X-Test", "second");
    EXPECT_EQ(response.GetHeader("X-Test"), "second");
}

TEST_F(HttpResponseTest, SerializeStatusLine) {
    response.SetStatus(HttpStatus::NotFound);
    std::string serialized = response.Serialize();
    EXPECT_NE(serialized.find("HTTP/1.1 404 Not Found\r\n"), std::string::npos);
}

TEST_F(HttpResponseTest, SerializeCreatedStatus) {
    response.SetStatus(HttpStatus::Created);
    std::string serialized = response.Serialize();
    EXPECT_NE(serialized.find("HTTP/1.1 201 Created\r\n"), std::string::npos);
}

TEST_F(HttpResponseTest, SerializeInternalServerError) {
    response.SetStatus(HttpStatus::InternalServerError);
    std::string serialized = response.Serialize();
    EXPECT_NE(serialized.find("HTTP/1.1 500 Internal Server Error\r\n"), std::string::npos);
}
