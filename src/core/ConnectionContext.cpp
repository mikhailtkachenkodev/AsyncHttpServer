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
    , m_sendBufferSize(0)
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

std::string ConnectionContext::GetReceiveBuffer() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_receiveBuffer;
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
    m_sendBufferSize = m_sendBuffer.size();
    m_bytesSent.store(0, std::memory_order_release);
}

void ConnectionContext::SetSendBuffer(std::string&& data) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_sendBuffer = std::move(data);
    m_sendBufferSize = m_sendBuffer.size();
    m_bytesSent.store(0, std::memory_order_release);
}

std::string ConnectionContext::GetSendBuffer() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_sendBuffer;
}

bool ConnectionContext::IsSendComplete() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_bytesSent.load(std::memory_order_acquire) >= m_sendBufferSize;
}

size_t ConnectionContext::GetRemainingBytes() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t sent = m_bytesSent.load(std::memory_order_acquire);
    if (sent >= m_sendBufferSize) {
        return 0;
    }
    return m_sendBufferSize - sent;
}

void ConnectionContext::SetTlsConnection(std::unique_ptr<security::TlsConnection> tls) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tlsConnection = std::move(tls);
}

void ConnectionContext::UpdateLastActivity() {
    m_lastActivity.store(std::chrono::steady_clock::now(), std::memory_order_release);
}

void ConnectionContext::Close() {
    std::lock_guard<std::mutex> lock(m_closeMutex);

    SOCKET sock = m_socket.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
    if (sock != INVALID_SOCKET) {
        shutdown(sock, SD_BOTH);
        closesocket(sock);
        m_state.store(ConnectionState::Closed, std::memory_order_release);
    }
}

} // namespace core
} // namespace http_server
