#pragma once

#include "http/HttpRequest.hpp"
#include <string>
#include <cstddef>

namespace http_server {
namespace http {

enum class ParseResult {
    Complete,
    NeedMoreData,
    MalformedRequest,
    RequestTooLarge,
    UnsupportedMethod
};

enum class ParserState {
    RequestLine,
    Headers,
    Body,
    Complete,
    Error
};

class HttpParser {
public:
    HttpParser();

    ParseResult Feed(const char* data, size_t length);
    ParseResult Feed(const std::string& data);

    bool IsComplete() const { return m_state == ParserState::Complete; }
    bool HasError() const { return m_state == ParserState::Error; }

    HttpRequest& GetRequest() { return m_request; }
    const HttpRequest& GetRequest() const { return m_request; }

    ParserState GetState() const { return m_state; }

    void Reset();

    size_t GetBytesConsumed() const { return m_bytesConsumed; }

    static constexpr size_t MAX_REQUEST_SIZE = 1024 * 1024;
    static constexpr size_t MAX_REQUEST_LINE_SIZE = 8192;
    static constexpr size_t MAX_HEADER_SIZE = 8192;
    static constexpr size_t MAX_HEADER_COUNT = 100;
    static constexpr size_t MAX_BODY_SIZE = 1024 * 1024;

private:
    bool TryParseRequestLine();
    bool TryParseHeaders();
    bool TryParseBody();
    bool ValidatePath(const std::string& path);

    std::string m_buffer;
    HttpRequest m_request;
    ParserState m_state;
    size_t m_contentLength;
    size_t m_headerCount;
    size_t m_bytesConsumed;
    ParseResult m_lastError;
};

} // namespace http
} // namespace http_server
