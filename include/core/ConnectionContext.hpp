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

    SOCKET GetSocket() const { return m_socket.load(std::memory_order_acquire); }
    bool IsHttps() const { return m_isHttps; }
    ConnectionState GetState() const { return m_state.load(std::memory_order_acquire); }
    void SetState(ConnectionState state) { m_state.store(state, std::memory_order_release); }

    void AppendToReceiveBuffer(const char* data, size_t length);
    std::string GetReceiveBuffer() const;
    void ClearReceiveBuffer();
    void ConsumeReceiveBuffer(size_t bytes);

    void SetSendBuffer(const std::string& data);
    void SetSendBuffer(std::string&& data);
    std::string GetSendBuffer() const;
    size_t GetBytesSent() const { return m_bytesSent.load(std::memory_order_acquire); }
    void AddBytesSent(size_t bytes) { m_bytesSent.fetch_add(bytes, std::memory_order_acq_rel); }
    void ResetSendProgress() { m_bytesSent.store(0, std::memory_order_release); }
    bool IsSendComplete() const;
    size_t GetRemainingBytes() const;

    void IncrementPendingOperations() { ++m_pendingOperations; }
    void DecrementPendingOperations() { --m_pendingOperations; }
    int GetPendingOperations() const { return m_pendingOperations.load(); }

    void SetTlsConnection(std::unique_ptr<security::TlsConnection> tls);
    security::TlsConnection* GetTlsConnection() { return m_tlsConnection.get(); }
    const security::TlsConnection* GetTlsConnection() const { return m_tlsConnection.get(); }

    bool IsKeepAlive() const { return m_keepAlive.load(std::memory_order_acquire); }
    void SetKeepAlive(bool keepAlive) { m_keepAlive.store(keepAlive, std::memory_order_release); }

    void UpdateLastActivity();
    std::chrono::steady_clock::time_point GetLastActivity() const { return m_lastActivity.load(std::memory_order_acquire); }

    void SetRemoteAddress(const std::string& address) { m_remoteAddress = address; }
    const std::string& GetRemoteAddress() const { return m_remoteAddress; }

    void Close();

private:
    std::atomic<SOCKET> m_socket;
    bool m_isHttps;
    std::atomic<ConnectionState> m_state;

    std::string m_receiveBuffer;
    std::string m_sendBuffer;
    std::atomic<size_t> m_bytesSent;
    size_t m_sendBufferSize;  // Cached size for thread-safe access

    std::atomic<int> m_pendingOperations;
    std::unique_ptr<security::TlsConnection> m_tlsConnection;

    std::atomic<bool> m_keepAlive;
    std::atomic<std::chrono::steady_clock::time_point> m_lastActivity;
    std::string m_remoteAddress;

    mutable std::mutex m_mutex;
    mutable std::mutex m_closeMutex;  // Separate mutex for Close() to avoid deadlock
};

using ConnectionContextPtr = std::shared_ptr<ConnectionContext>;

} // namespace core
} // namespace http_server
