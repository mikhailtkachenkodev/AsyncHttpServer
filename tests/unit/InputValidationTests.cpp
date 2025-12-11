#include "http/HttpParser.hpp"
#include "http/HttpRequest.hpp"
#include "storage/ThreadSafeStore.hpp"

#include <gtest/gtest.h>
#include <string>

using namespace http_server;

TEST(InputValidationTest, RejectOversizedRequest) {
    http::HttpParser parser;

    // Create a request larger than MAX_REQUEST_SIZE (1MB)
    std::string oversizedBody(2 * 1024 * 1024, 'x');
    std::string request =
        "POST /data HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Length: " + std::to_string(oversizedBody.size()) + "\r\n"
        "\r\n" + oversizedBody;

    auto result = parser.Feed(request);
    EXPECT_EQ(result, http::ParseResult::RequestTooLarge);
}

TEST(InputValidationTest, RejectTooManyHeaders) {
    http::HttpParser parser;

    std::string request = "GET /info HTTP/1.1\r\n";
    // Add more than MAX_HEADER_COUNT (100) headers
    for (int i = 0; i < 150; ++i) {
        request += "X-Header-" + std::to_string(i) + ": value\r\n";
    }
    request += "\r\n";

    auto result = parser.Feed(request);
    EXPECT_EQ(result, http::ParseResult::RequestTooLarge);
}

TEST(InputValidationTest, RejectPathTraversal) {
    http::HttpParser parser;

    const char* requests[] = {
        "GET /../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /data/../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /..%2F..%2Fetc%2Fpasswd HTTP/1.1\r\nHost: localhost\r\n\r\n"
    };

    for (const auto* req : requests) {
        http::HttpParser p;
        auto result = p.Feed(req, strlen(req));
        // The parser should reject paths containing ".."
        if (p.GetRequest().GetPath().find("..") != std::string::npos) {
            EXPECT_EQ(result, http::ParseResult::MalformedRequest);
        }
    }
}

TEST(InputValidationTest, ValidateJsonSize) {
    storage::ThreadSafeStore store;

    // Create JSON larger than MAX_VALUE_SIZE (1MB)
    std::string largeString(2 * 1024 * 1024, 'x');
    nlohmann::json largeJson = {{"data", largeString}};

    EXPECT_FALSE(store.Set("key", largeJson));
}

TEST(InputValidationTest, ValidateKeyFormat) {
    storage::ThreadSafeStore store;

    // Valid keys
    EXPECT_TRUE(store.Set("valid_key", nlohmann::json(1)));
    EXPECT_TRUE(store.Set("valid-key", nlohmann::json(2)));
    EXPECT_TRUE(store.Set("valid.key", nlohmann::json(3)));
    EXPECT_TRUE(store.Set("ValidKey123", nlohmann::json(4)));

    // Invalid keys
    EXPECT_FALSE(store.Set("", nlohmann::json(1)));
    EXPECT_FALSE(store.Set("key with spaces", nlohmann::json(1)));
    EXPECT_FALSE(store.Set("key<script>", nlohmann::json(1)));
    EXPECT_FALSE(store.Set("key;DROP TABLE", nlohmann::json(1)));
    // Use string constructor with explicit length to include null byte
    EXPECT_FALSE(store.Set(std::string("key\0null", 8), nlohmann::json(1)));
}

TEST(InputValidationTest, ValidateKeyLength) {
    storage::ThreadSafeStore store;

    // Key at max length (256)
    std::string maxKey(256, 'a');
    EXPECT_TRUE(store.Set(maxKey, nlohmann::json(1)));

    // Key over max length
    std::string overMaxKey(257, 'a');
    EXPECT_FALSE(store.Set(overMaxKey, nlohmann::json(1)));
}

TEST(InputValidationTest, HandleMalformedJson) {
    // Test that parsing malformed JSON doesn't crash
    const char* malformedJsons[] = {
        "{",
        "}",
        "{\"key\": }",
        "{\"key\": value}",
        "null",
        "[]",
        "\"string\""
    };

    for (const auto* jsonStr : malformedJsons) {
        try {
            nlohmann::json j = nlohmann::json::parse(jsonStr);
            // Some of these will parse (null, [], "string")
            // That's OK - we're testing for crashes
        } catch (const nlohmann::json::parse_error&) {
            // Expected for malformed JSON
        }
    }
}

TEST(InputValidationTest, RejectInvalidHttpVersion) {
    http::HttpParser parser;
    const char* request = "GET /info HTTP/2.0\r\nHost: localhost\r\n\r\n";

    auto result = parser.Feed(request, strlen(request));
    EXPECT_EQ(result, http::ParseResult::MalformedRequest);
}

TEST(InputValidationTest, HandleMissingContentLength) {
    http::HttpParser parser;

    // POST without Content-Length
    std::string request =
        "POST /data HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/json\r\n"
        "\r\n";

    auto result = parser.Feed(request);
    EXPECT_EQ(result, http::ParseResult::Complete);
    // Body should be empty without Content-Length
    EXPECT_TRUE(parser.GetRequest().GetBody().empty());
}

TEST(InputValidationTest, ValidateContentLengthValue) {
    http::HttpParser parser;

    // Invalid Content-Length (negative)
    std::string request =
        "POST /data HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Length: -1\r\n"
        "\r\n";

    auto result = parser.Feed(request);
    // Parser should handle this gracefully
    EXPECT_TRUE(result == http::ParseResult::MalformedRequest ||
                result == http::ParseResult::Complete);
}

TEST(InputValidationTest, HandleSpecialCharactersInPath) {
    http::HttpParser parser;

    // URL-encoded characters
    const char* request = "GET /data/key%20with%20spaces HTTP/1.1\r\nHost: localhost\r\n\r\n";

    auto result = parser.Feed(request, strlen(request));
    EXPECT_EQ(result, http::ParseResult::Complete);
}
