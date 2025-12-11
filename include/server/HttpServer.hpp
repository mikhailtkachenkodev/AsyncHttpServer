#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <WinSock2.h>

#include "core/WinsockInit.hpp"
#include "core/IoCompletionPort.hpp"
#include "core/ThreadPool.hpp"
#include "core/ConnectionContext.hpp"
#include "core/OverlappedContext.hpp"
#include "http/HttpRouter.hpp"
#include "http/HttpParser.hpp"
#include "storage/ThreadSafeStore.hpp"
#include "handlers/InfoHandler.hpp"
#include "handlers/DataHandler.hpp"

#include <memory>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <string>
#include <chrono>

namespace http_server {

namespace security {
class SchannelContext;
class TlsConnection;
}

struct ServerConfig {
    uint16_t port = 8080;
    uint16_t httpsPort = 8443;
    bool enableHttps = false;
    std::wstring certificateSubject;
    std::string bindAddress = "0.0.0.0";
    size_t threadPoolSize = 0;
    std::chrono::seconds connectionTimeout{60};
    size_t maxConnections = 10000;
    std::string serverVersion = "1.0";
};

class HttpServer {
public:
    explicit HttpServer(const ServerConfig& config = ServerConfig{});
    ~HttpServer();

    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    void Start();
    void Stop();
    bool IsRunning() const { return m_running.load(std::memory_order_acquire); }

    uint16_t GetPort() const { return m_port; }
    uint16_t GetHttpsPort() const { return m_httpsPort; }

    http::HttpRouter& GetRouter() { return m_router; }

    int GetActiveConnections() const { return m_activeConnections.load(); }

private:
    void InitializeWinsock();
    void InitializeIocp();
    void InitializeThreadPool();
    void InitializeRoutes();
    void InitializeListenSocket();
    void InitializeHttpsListenSocket();
    void InitializeSchannel();

    SOCKET CreateListenSocket(uint16_t port, bool isHttps);
    void PostAccept(SOCKET listenSocket, bool isHttps);

    void HandleCompletion(const core::CompletionResult& result);

    void HandleAccept(core::OverlappedContext* context, DWORD bytesTransferred);
    void HandleReceive(const core::ConnectionContextPtr& connection, DWORD bytesTransferred);
    void HandleSend(const core::ConnectionContextPtr& connection, DWORD bytesTransferred);
    void HandleDisconnect(const core::ConnectionContextPtr& connection);

    void HandleTlsHandshake(const core::ConnectionContextPtr& connection, const char* data, size_t length);
    void ProcessTlsDecryptedData(const core::ConnectionContextPtr& connection);

    void ProcessRequest(const core::ConnectionContextPtr& connection);
    void SendResponse(const core::ConnectionContextPtr& connection, const http::HttpResponse& response);

    void PostReceive(const core::ConnectionContextPtr& connection);
    void PostSend(const core::ConnectionContextPtr& connection);

    core::ConnectionContextPtr CreateConnection(SOCKET socket, bool isHttps);
    void RemoveConnection(SOCKET socket);

    void WaitForConnections(std::chrono::seconds timeout);

    ServerConfig m_config;
    uint16_t m_port;
    uint16_t m_httpsPort;

    std::unique_ptr<core::WinsockInit> m_winsock;
    std::unique_ptr<core::IoCompletionPort> m_iocp;
    std::unique_ptr<core::ThreadPool> m_threadPool;

    SOCKET m_listenSocket;
    SOCKET m_httpsListenSocket;

    std::unique_ptr<security::SchannelContext> m_schannelContext;

    http::HttpRouter m_router;
    std::shared_ptr<storage::ThreadSafeStore> m_dataStore;
    std::unique_ptr<handlers::InfoHandler> m_infoHandler;
    std::unique_ptr<handlers::DataHandler> m_dataHandler;

    std::unordered_map<SOCKET, core::ConnectionContextPtr> m_connections;
    mutable std::mutex m_connectionsMutex;
    std::atomic<int> m_activeConnections{0};

    std::atomic<bool> m_running{false};

    static constexpr int ACCEPT_POOL_SIZE = 10;
    std::vector<std::unique_ptr<core::OverlappedContext>> m_acceptContexts;
    std::mutex m_acceptMutex;
};

} // namespace http_server
