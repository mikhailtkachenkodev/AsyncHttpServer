#include "http/HttpParser.hpp"
#include <algorithm>
#include <cctype>

namespace http_server {
namespace http {

HttpParser::HttpParser()
    : m_state(ParserState::RequestLine)
    , m_contentLength(0)
    , m_headerCount(0)
    , m_bytesConsumed(0)
    , m_lastError(ParseResult::NeedMoreData) {
}

ParseResult HttpParser::Feed(const char* data, size_t length) {
    m_buffer.append(data, length);

    if (m_buffer.size() > MAX_REQUEST_SIZE) {
        m_state = ParserState::Error;
        m_lastError = ParseResult::RequestTooLarge;
        return ParseResult::RequestTooLarge;
    }

    while (true) {
        switch (m_state) {
            case ParserState::RequestLine:
                if (!TryParseRequestLine()) {
                    return m_lastError;
                }
                break;

            case ParserState::Headers:
                if (!TryParseHeaders()) {
                    return m_lastError;
                }
                break;

            case ParserState::Body:
                if (!TryParseBody()) {
                    return m_lastError;
                }
                m_state = ParserState::Complete;
                return ParseResult::Complete;

            case ParserState::Complete:
                return ParseResult::Complete;

            case ParserState::Error:
                return m_lastError;
        }
    }
}

ParseResult HttpParser::Feed(const std::string& data) {
    return Feed(data.data(), data.size());
}

void HttpParser::Reset() {
    m_buffer.clear();
    m_request.Clear();
    m_state = ParserState::RequestLine;
    m_contentLength = 0;
    m_headerCount = 0;
    m_bytesConsumed = 0;
    m_lastError = ParseResult::NeedMoreData;
}

bool HttpParser::TryParseRequestLine() {
    auto pos = m_buffer.find("\r\n");
    if (pos == std::string::npos) {
        if (m_buffer.size() > MAX_REQUEST_LINE_SIZE) {
            m_state = ParserState::Error;
            m_lastError = ParseResult::RequestTooLarge;
            return false;
        }
        m_lastError = ParseResult::NeedMoreData;
        return false;
    }

    std::string line = m_buffer.substr(0, pos);
    m_buffer.erase(0, pos + 2);
    m_bytesConsumed += pos + 2;

    size_t methodEnd = line.find(' ');
    if (methodEnd == std::string::npos) {
        m_state = ParserState::Error;
        m_lastError = ParseResult::MalformedRequest;
        return false;
    }

    std::string methodStr = line.substr(0, methodEnd);

    size_t pathStart = methodEnd + 1;
    size_t pathEnd = line.find(' ', pathStart);
    if (pathEnd == std::string::npos) {
        m_state = ParserState::Error;
        m_lastError = ParseResult::MalformedRequest;
        return false;
    }

    std::string path = line.substr(pathStart, pathEnd - pathStart);

    std::string version = line.substr(pathEnd + 1);
    if (version != "HTTP/1.0" && version != "HTTP/1.1") {
        m_state = ParserState::Error;
        m_lastError = ParseResult::MalformedRequest;
        return false;
    }
    m_request.SetHttpVersion(version);

    HttpMethod method = StringToMethod(methodStr);
    if (method != HttpMethod::GET && method != HttpMethod::POST) {
        m_state = ParserState::Error;
        m_lastError = ParseResult::UnsupportedMethod;
        return false;
    }
    m_request.SetMethod(method);

    if (!ValidatePath(path)) {
        m_state = ParserState::Error;
        m_lastError = ParseResult::MalformedRequest;
        return false;
    }
    m_request.SetPath(path);

    m_state = ParserState::Headers;
    return true;
}

bool HttpParser::TryParseHeaders() {
    while (true) {
        auto pos = m_buffer.find("\r\n");
        if (pos == std::string::npos) {
            if (m_buffer.size() > MAX_HEADER_SIZE) {
                m_state = ParserState::Error;
                m_lastError = ParseResult::RequestTooLarge;
                return false;
            }
            m_lastError = ParseResult::NeedMoreData;
            return false;
        }

        if (pos == 0) {
            m_buffer.erase(0, 2);
            m_bytesConsumed += 2;

            auto contentLength = m_request.GetHeader("content-length");
            if (contentLength) {
                try {
                    if (!contentLength->empty() && (*contentLength)[0] == '-') {
                        m_state = ParserState::Error;
                        m_lastError = ParseResult::MalformedRequest;
                        return false;
                    }
                    m_contentLength = std::stoull(*contentLength);
                    if (m_contentLength > MAX_BODY_SIZE) {
                        m_state = ParserState::Error;
                        m_lastError = ParseResult::RequestTooLarge;
                        return false;
                    }
                } catch (...) {
                    m_state = ParserState::Error;
                    m_lastError = ParseResult::MalformedRequest;
                    return false;
                }
            }

            m_state = ParserState::Body;
            return true;
        }

        if (++m_headerCount > MAX_HEADER_COUNT) {
            m_state = ParserState::Error;
            m_lastError = ParseResult::RequestTooLarge;
            return false;
        }

        std::string line = m_buffer.substr(0, pos);
        m_buffer.erase(0, pos + 2);
        m_bytesConsumed += pos + 2;

        auto colonPos = line.find(':');
        if (colonPos == std::string::npos) {
            m_state = ParserState::Error;
            m_lastError = ParseResult::MalformedRequest;
            return false;
        }

        std::string name = line.substr(0, colonPos);
        std::string value = line.substr(colonPos + 1);

        size_t valueStart = value.find_first_not_of(" \t");
        if (valueStart != std::string::npos) {
            value = value.substr(valueStart);
        }
        size_t valueEnd = value.find_last_not_of(" \t");
        if (valueEnd != std::string::npos) {
            value = value.substr(0, valueEnd + 1);
        }

        m_request.AddHeader(name, value);
    }
}

bool HttpParser::TryParseBody() {
    if (m_contentLength == 0) {
        return true;
    }

    if (m_buffer.size() < m_contentLength) {
        m_lastError = ParseResult::NeedMoreData;
        return false;
    }

    m_request.SetBody(m_buffer.substr(0, m_contentLength));
    m_buffer.erase(0, m_contentLength);
    m_bytesConsumed += m_contentLength;

    return true;
}

bool HttpParser::ValidatePath(const std::string& path) {
    if (path.empty() || path[0] != '/') {
        return false;
    }

    if (path.find('\0') != std::string::npos) {
        return false;
    }

    if (path.find("..") != std::string::npos) {
        return false;
    }

    if (path.size() > 2048) {
        return false;
    }

    return true;
}

} // namespace http
} // namespace http_server
