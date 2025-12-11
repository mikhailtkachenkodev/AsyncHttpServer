#include "core/ConnectionContext.hpp"
#include "security/TlsConnection.hpp"
#include "utils/Logger.hpp"

namespace http_server {
namespace core {

ConnectionContext::ConnectionContext(SOCKET socket, bool isHttps)
    : m_socket(socket)
    , m_isHttps(isHttps)
    , m_state(ConnectionState::Accepting)
    , m_bytesSent(0)
    , m_pendingOperations(0)
    , m_keepAlive(true)
    , m_lastActivity(std::chrono::steady_clock::now()) {
}

ConnectionContext::~ConnectionContext() {
    Close();
}

void ConnectionContext::AppendToReceiveBuffer(const char* data, size_t length) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_receiveBuffer.append(data, length);
}

void ConnectionContext::ClearReceiveBuffer() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_receiveBuffer.clear();
}

void ConnectionContext::ConsumeReceiveBuffer(size_t bytes) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (bytes >= m_receiveBuffer.size()) {
        m_receiveBuffer.clear();
    } else {
        m_receiveBuffer.erase(0, bytes);
    }
}

void ConnectionContext::SetSendBuffer(const std::string& data) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_sendBuffer = data;
    m_bytesSent = 0;
}

void ConnectionContext::SetSendBuffer(std::string&& data) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_sendBuffer = std::move(data);
    m_bytesSent = 0;
}

void ConnectionContext::SetTlsConnection(std::unique_ptr<security::TlsConnection> tls) {
    m_tlsConnection = std::move(tls);
}

void ConnectionContext::UpdateLastActivity() {
    m_lastActivity = std::chrono::steady_clock::now();
}

void ConnectionContext::Close() {
    if (m_socket != INVALID_SOCKET) {
        shutdown(m_socket, SD_BOTH);
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        m_state = ConnectionState::Closed;
    }
}

} // namespace core
} // namespace http_server
