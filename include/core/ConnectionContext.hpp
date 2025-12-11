#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <WinSock2.h>
#include <string>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <vector>

namespace http_server {

namespace security {
class TlsConnection;
}

namespace core {

struct OverlappedContext;

enum class ConnectionState {
    Accepting,
    TlsHandshaking,
    Reading,
    Processing,
    Writing,
    Closing,
    Closed
};

class ConnectionContext {
public:
    explicit ConnectionContext(SOCKET socket, bool isHttps = false);
    ~ConnectionContext();

    ConnectionContext(const ConnectionContext&) = delete;
    ConnectionContext& operator=(const ConnectionContext&) = delete;

    SOCKET GetSocket() const { return m_socket; }
    bool IsHttps() const { return m_isHttps; }
    ConnectionState GetState() const { return m_state; }
    void SetState(ConnectionState state) { m_state = state; }

    void AppendToReceiveBuffer(const char* data, size_t length);
    const std::string& GetReceiveBuffer() const { return m_receiveBuffer; }
    void ClearReceiveBuffer();
    void ConsumeReceiveBuffer(size_t bytes);

    void SetSendBuffer(const std::string& data);
    void SetSendBuffer(std::string&& data);
    const std::string& GetSendBuffer() const { return m_sendBuffer; }
    size_t GetBytesSent() const { return m_bytesSent; }
    void AddBytesSent(size_t bytes) { m_bytesSent += bytes; }
    void ResetSendProgress() { m_bytesSent = 0; }
    bool IsSendComplete() const { return m_bytesSent >= m_sendBuffer.size(); }
    size_t GetRemainingBytes() const { return m_sendBuffer.size() - m_bytesSent; }

    void IncrementPendingOperations() { ++m_pendingOperations; }
    void DecrementPendingOperations() { --m_pendingOperations; }
    int GetPendingOperations() const { return m_pendingOperations.load(); }

    void SetTlsConnection(std::unique_ptr<security::TlsConnection> tls);
    security::TlsConnection* GetTlsConnection() { return m_tlsConnection.get(); }
    const security::TlsConnection* GetTlsConnection() const { return m_tlsConnection.get(); }

    bool IsKeepAlive() const { return m_keepAlive; }
    void SetKeepAlive(bool keepAlive) { m_keepAlive = keepAlive; }

    void UpdateLastActivity();
    std::chrono::steady_clock::time_point GetLastActivity() const { return m_lastActivity; }

    void SetRemoteAddress(const std::string& address) { m_remoteAddress = address; }
    const std::string& GetRemoteAddress() const { return m_remoteAddress; }

    void Close();

private:
    SOCKET m_socket;
    bool m_isHttps;
    ConnectionState m_state;

    std::string m_receiveBuffer;
    std::string m_sendBuffer;
    size_t m_bytesSent;

    std::atomic<int> m_pendingOperations;
    std::unique_ptr<security::TlsConnection> m_tlsConnection;

    bool m_keepAlive;
    std::chrono::steady_clock::time_point m_lastActivity;
    std::string m_remoteAddress;

    mutable std::mutex m_mutex;
};

using ConnectionContextPtr = std::shared_ptr<ConnectionContext>;

} // namespace core
} // namespace http_server
