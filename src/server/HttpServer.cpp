#include "server/HttpServer.hpp"
#include "security/SchannelContext.hpp"
#include "security/TlsConnection.hpp"
#include "utils/ErrorHandler.hpp"
#include "utils/Logger.hpp"

#include <WS2tcpip.h>

namespace http_server {

HttpServer::HttpServer(const ServerConfig& config)
    : m_config(config)
    , m_port(config.port)
    , m_httpsPort(config.httpsPort)
    , m_listenSocket(INVALID_SOCKET)
    , m_httpsListenSocket(INVALID_SOCKET)
    , m_dataStore(std::make_shared<storage::ThreadSafeStore>())
    , m_infoHandler(std::make_unique<handlers::InfoHandler>())
    , m_dataHandler(std::make_unique<handlers::DataHandler>(m_dataStore)) {

    m_infoHandler->SetVersion(config.serverVersion);
    m_infoHandler->SetConnectionCounter([this]() { return GetActiveConnections(); });
}

HttpServer::~HttpServer() {
    Stop();
}

void HttpServer::Start() {
    if (m_running.load(std::memory_order_acquire)) {
        return;
    }

    utils::Logger::Info("Starting HTTP server...");

    InitializeWinsock();
    InitializeIocp();
    InitializeRoutes();
    InitializeListenSocket();

    if (m_config.enableHttps) {
        InitializeSchannel();
        InitializeHttpsListenSocket();
    }

    InitializeThreadPool();

    for (int i = 0; i < ACCEPT_POOL_SIZE; ++i) {
        PostAccept(m_listenSocket, false);
        if (m_config.enableHttps && m_httpsListenSocket != INVALID_SOCKET) {
            PostAccept(m_httpsListenSocket, true);
        }
    }

    m_running.store(true, std::memory_order_release);
    utils::Logger::Info("HTTP server started on port " + std::to_string(m_port));

    if (m_config.enableHttps && m_httpsListenSocket != INVALID_SOCKET) {
        utils::Logger::Info("HTTPS server started on port " + std::to_string(m_httpsPort));
    }
}

void HttpServer::Stop() {
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }

    utils::Logger::Info("Stopping HTTP server...");
    m_running.store(false, std::memory_order_release);

    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }

    if (m_httpsListenSocket != INVALID_SOCKET) {
        closesocket(m_httpsListenSocket);
        m_httpsListenSocket = INVALID_SOCKET;
    }

    WaitForConnections(std::chrono::seconds(30));

    {
        std::lock_guard<std::mutex> lock(m_connectionsMutex);
        for (auto& [socket, context] : m_connections) {
            context->Close();
        }
        m_connections.clear();
    }

    if (m_threadPool) {
        m_threadPool->Stop();
    }

    utils::Logger::Info("HTTP server stopped");
}

void HttpServer::InitializeWinsock() {
    m_winsock = std::make_unique<core::WinsockInit>();
}

void HttpServer::InitializeIocp() {
    m_iocp = std::make_unique<core::IoCompletionPort>();
}

void HttpServer::InitializeThreadPool() {
    m_threadPool = std::make_unique<core::ThreadPool>(*m_iocp);
    m_threadPool->SetCompletionHandler([this](const core::CompletionResult& result) {
        HandleCompletion(result);
    });

    size_t threadCount = m_config.threadPoolSize;
    if (threadCount == 0) {
        threadCount = core::ThreadPool::GetOptimalThreadCount();
    }
    m_threadPool->Start(threadCount);
}

void HttpServer::InitializeRoutes() {
    m_router.Get("/info", [this](http::HttpRequest& req) {
        return m_infoHandler->Handle(req);
    });

    m_router.Post("/data", [this](http::HttpRequest& req) {
        return m_dataHandler->HandlePost(req);
    });

    m_router.Get("/data/:key", [this](http::HttpRequest& req) {
        return m_dataHandler->HandleGet(req);
    });

    m_router.Get("/data", [this](http::HttpRequest& req) {
        return m_dataHandler->HandleGet(req);
    });
}

void HttpServer::InitializeListenSocket() {
    m_listenSocket = CreateListenSocket(m_config.port, false);
    m_iocp->Associate(m_listenSocket, reinterpret_cast<ULONG_PTR>(nullptr));
}

void HttpServer::InitializeHttpsListenSocket() {
    if (!m_config.enableHttps) {
        return;
    }

    try {
        m_httpsListenSocket = CreateListenSocket(m_config.httpsPort, true);
        m_iocp->Associate(m_httpsListenSocket, reinterpret_cast<ULONG_PTR>(nullptr));
    } catch (const std::exception& e) {
        utils::Logger::Warning("Failed to initialize HTTPS listen socket: " + std::string(e.what()));
        m_httpsListenSocket = INVALID_SOCKET;
    }
}

void HttpServer::InitializeSchannel() {
    if (!m_config.enableHttps || m_config.certificateSubject.empty()) {
        return;
    }

    try {
        m_schannelContext = std::make_unique<security::SchannelContext>();
        if (!m_schannelContext->Initialize(m_config.certificateSubject)) {
            utils::Logger::Warning("Failed to initialize Schannel, HTTPS disabled");
            m_schannelContext.reset();
        }
    } catch (const std::exception& e) {
        utils::Logger::Warning("Schannel initialization failed: " + std::string(e.what()));
        m_schannelContext.reset();
    }
}

SOCKET HttpServer::CreateListenSocket(uint16_t port, bool isHttps) {
    SOCKET sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        throw core::WinsockException("Failed to create listen socket", WSAGetLastError());
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&optval), sizeof(optval));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, m_config.bindAddress.c_str(), &addr.sin_addr);

    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        closesocket(sock);
        throw core::WinsockException("Failed to bind socket to port " + std::to_string(port), error);
    }

    if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        closesocket(sock);
        throw core::WinsockException("Failed to listen on socket", error);
    }

    sockaddr_in boundAddr{};
    int addrLen = sizeof(boundAddr);
    if (getsockname(sock, reinterpret_cast<sockaddr*>(&boundAddr), &addrLen) == 0) {
        if (port == 0) {
            if (isHttps) {
                m_httpsPort = ntohs(boundAddr.sin_port);
            } else {
                m_port = ntohs(boundAddr.sin_port);
            }
        }
    }

    return sock;
}

void HttpServer::PostAccept(SOCKET listenSocket, bool isHttps) {
    SOCKET acceptSocket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (acceptSocket == INVALID_SOCKET) {
        utils::Logger::Error("Failed to create accept socket: " + utils::ErrorHandler::GetWsaErrorMessage());
        return;
    }

    auto context = std::make_unique<core::OverlappedContext>();
    context->PrepareForAccept(acceptSocket);
    context->connection = reinterpret_cast<core::ConnectionContext*>(isHttps ? 1 : 0);

    DWORD bytesReceived = 0;
    LPFN_ACCEPTEX acceptEx = core::WinsockInit::GetAcceptEx();

    BOOL result = acceptEx(
        listenSocket,
        acceptSocket,
        context->buffer.data(),
        0,
        sizeof(sockaddr_in) + 16,
        sizeof(sockaddr_in) + 16,
        &bytesReceived,
        context.get()
    );

    if (!result && WSAGetLastError() != ERROR_IO_PENDING) {
        int error = WSAGetLastError();
        closesocket(acceptSocket);
        utils::Logger::Error("AcceptEx failed: " + utils::ErrorHandler::GetWsaErrorMessage(error));
        return;
    }

    std::lock_guard<std::mutex> lock(m_acceptMutex);
    m_acceptContexts.push_back(std::move(context));
}

void HttpServer::HandleCompletion(const core::CompletionResult& result) {
    if (result.overlapped == nullptr) {
        return;
    }

    auto* context = static_cast<core::OverlappedContext*>(result.overlapped);

    // AcceptEx with dwReceiveDataLength = 0 legitimately returns bytesTransferred = 0
    if (context->operation == core::IoOperation::Accept) {
        if (result.success) {
            HandleAccept(context, result.bytesTransferred);
        }
        return;
    }

    if (!result.success || result.bytesTransferred == 0) {
        if (context->connection) {
            HandleDisconnect(context->connection);
        }
        return;
    }

    switch (context->operation) {
        case core::IoOperation::Receive:
            HandleReceive(context, result.bytesTransferred);
            break;
        case core::IoOperation::Send:
            HandleSend(context, result.bytesTransferred);
            break;
        case core::IoOperation::Disconnect:
            if (context->connection) {
                HandleDisconnect(context->connection);
            }
            break;
        default:
            break;
    }
}

void HttpServer::HandleAccept(core::OverlappedContext* context, DWORD /*bytesTransferred*/) {
    SOCKET acceptSocket = context->acceptSocket;
    bool isHttps = context->connection != nullptr;

    {
        std::lock_guard<std::mutex> lock(m_acceptMutex);
        auto it = std::find_if(m_acceptContexts.begin(), m_acceptContexts.end(),
            [context](const auto& ptr) { return ptr.get() == context; });
        if (it != m_acceptContexts.end()) {
            m_acceptContexts.erase(it);
        }
    }

    SOCKET listenSocket = isHttps ? m_httpsListenSocket : m_listenSocket;
    if (listenSocket != INVALID_SOCKET && m_running.load(std::memory_order_acquire)) {
        PostAccept(listenSocket, isHttps);
    }

    if (m_activeConnections.load() >= static_cast<int>(m_config.maxConnections)) {
        utils::Logger::Warning("Connection limit reached, rejecting connection");
        closesocket(acceptSocket);
        return;
    }

    setsockopt(acceptSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
               reinterpret_cast<char*>(&listenSocket), sizeof(listenSocket));

    auto connection = CreateConnection(acceptSocket, isHttps);
    if (!connection) {
        closesocket(acceptSocket);
        return;
    }

    try {
        m_iocp->Associate(acceptSocket, reinterpret_cast<ULONG_PTR>(connection.get()));
    } catch (const core::IocpException& e) {
        utils::Logger::Error("Failed to associate socket with IOCP: " + std::string(e.what()));
        closesocket(acceptSocket);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_connectionsMutex);
        m_connections[acceptSocket] = connection;
    }
    m_activeConnections.fetch_add(1, std::memory_order_relaxed);

    connection->SetState(core::ConnectionState::Reading);

    PostReceive(connection.get());
}

void HttpServer::HandleReceive(core::OverlappedContext* context, DWORD bytesTransferred) {
    auto* connection = context->connection;
    if (!connection) {
        return;
    }

    connection->UpdateLastActivity();

    connection->AppendToReceiveBuffer(context->buffer.data(), bytesTransferred);

    if (connection->IsHttps()) {
        auto* tls = connection->GetTlsConnection();
        if (tls && !tls->IsHandshakeComplete()) {
            const auto& recvBuf = connection->GetReceiveBuffer();
            HandleTlsHandshake(connection, recvBuf.data(), recvBuf.size());
            return;
        } else if (tls) {
            ProcessTlsDecryptedData(connection);
            return;
        }
    }

    ProcessRequest(connection);
}

void HttpServer::HandleSend(core::OverlappedContext* context, DWORD bytesTransferred) {
    auto* connection = context->connection;
    if (!connection) {
        return;
    }

    connection->UpdateLastActivity();
    connection->AddBytesSent(bytesTransferred);

    if (!connection->IsSendComplete()) {
        PostSend(connection);
    } else {
        connection->ResetSendProgress();

        if (connection->IsHttps()) {
            auto* tls = connection->GetTlsConnection();
            if (tls && !tls->IsHandshakeComplete()) {
                tls->ClearHandshakeResponse();
                PostReceive(connection);
                return;
            }
        }

        if (connection->IsKeepAlive()) {
            connection->ClearReceiveBuffer();
            connection->SetState(core::ConnectionState::Reading);
            PostReceive(connection);
        } else {
            HandleDisconnect(connection);
        }
    }
}

void HttpServer::HandleDisconnect(core::ConnectionContext* connection) {
    if (!connection) {
        return;
    }

    SOCKET socket = connection->GetSocket();
    CloseConnection(connection);
    RemoveConnection(socket);
}

void HttpServer::HandleTlsHandshake(core::ConnectionContext* connection, const char* data, size_t length) {
    auto* tls = connection->GetTlsConnection();
    if (!tls) {
        HandleDisconnect(connection);
        return;
    }

    auto result = tls->DoHandshake(data, length);

    switch (result) {
        case security::HandshakeResult::Complete:
            connection->ClearReceiveBuffer();
            connection->SetState(core::ConnectionState::Reading);
            PostReceive(connection);
            break;

        case security::HandshakeResult::ContinueNeeded: {
            connection->ClearReceiveBuffer();
            auto& responseData = tls->GetHandshakeResponse();
            if (!responseData.empty()) {
                connection->SetSendBuffer(std::string(responseData.begin(), responseData.end()));
                PostSend(connection);
            }
            break;
        }

        case security::HandshakeResult::NeedMoreData:
            PostReceive(connection);
            break;

        case security::HandshakeResult::Failed:
            utils::Logger::Warning("TLS handshake failed");
            HandleDisconnect(connection);
            break;
    }
}

void HttpServer::ProcessTlsDecryptedData(core::ConnectionContext* connection) {
    auto* tls = connection->GetTlsConnection();
    if (!tls) {
        return;
    }

    auto decrypted = tls->Decrypt(
        connection->GetReceiveBuffer().data(),
        connection->GetReceiveBuffer().size()
    );

    if (decrypted.empty()) {
        PostReceive(connection);
        return;
    }

    connection->ClearReceiveBuffer();
    connection->AppendToReceiveBuffer(decrypted.data(), decrypted.size());
    ProcessRequest(connection);
}

void HttpServer::ProcessRequest(core::ConnectionContext* connection) {
    http::HttpParser parser;
    auto result = parser.Feed(connection->GetReceiveBuffer());

    switch (result) {
        case http::ParseResult::Complete: {
            connection->SetState(core::ConnectionState::Processing);
            http::HttpRequest& request = parser.GetRequest();
            connection->SetKeepAlive(request.IsKeepAlive());

            http::HttpResponse response = m_router.Route(request);
            response.SetKeepAlive(connection->IsKeepAlive());

            SendResponse(connection, response);
            break;
        }

        case http::ParseResult::NeedMoreData:
            PostReceive(connection);
            break;

        case http::ParseResult::MalformedRequest:
            SendResponse(connection, http::HttpResponse::BadRequest("Malformed request"));
            break;

        case http::ParseResult::RequestTooLarge:
            SendResponse(connection, http::HttpResponse::BadRequest("Request too large"));
            break;

        case http::ParseResult::UnsupportedMethod:
            SendResponse(connection, http::HttpResponse::MethodNotAllowed());
            break;
    }
}

void HttpServer::SendResponse(core::ConnectionContext* connection, const http::HttpResponse& response) {
    std::string data = response.Serialize();

    if (connection->IsHttps()) {
        auto* tls = connection->GetTlsConnection();
        if (tls && tls->IsHandshakeComplete()) {
            auto encrypted = tls->Encrypt(data.data(), data.size());
            connection->SetSendBuffer(std::string(encrypted.begin(), encrypted.end()));
        } else {
            connection->SetSendBuffer(std::move(data));
        }
    } else {
        connection->SetSendBuffer(std::move(data));
    }

    connection->SetState(core::ConnectionState::Writing);
    PostSend(connection);
}

void HttpServer::PostReceive(core::ConnectionContext* connection) {
    auto context = core::CreateOverlappedContext();
    context->PrepareForReceive();
    context->connection = connection;

    connection->IncrementPendingOperations();

    DWORD flags = 0;
    DWORD bytesReceived = 0;

    int result = WSARecv(
        connection->GetSocket(),
        &context->wsaBuf,
        1,
        &bytesReceived,
        &flags,
        context.get(),
        nullptr
    );

    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        connection->DecrementPendingOperations();
        utils::Logger::Debug("WSARecv failed: " + utils::ErrorHandler::GetWsaErrorMessage());
        HandleDisconnect(connection);
        return;
    }

    context.release();
}

void HttpServer::PostSend(core::ConnectionContext* connection) {
    const std::string& buffer = connection->GetSendBuffer();
    size_t offset = connection->GetBytesSent();
    size_t remaining = connection->GetRemainingBytes();

    auto context = core::CreateOverlappedContext();
    context->PrepareForSend(buffer.data() + offset, remaining);
    context->connection = connection;

    connection->IncrementPendingOperations();

    DWORD bytesSent = 0;

    int result = WSASend(
        connection->GetSocket(),
        &context->wsaBuf,
        1,
        &bytesSent,
        0,
        context.get(),
        nullptr
    );

    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        connection->DecrementPendingOperations();
        utils::Logger::Debug("WSASend failed: " + utils::ErrorHandler::GetWsaErrorMessage());
        HandleDisconnect(connection);
        return;
    }

    context.release();
}

core::ConnectionContextPtr HttpServer::CreateConnection(SOCKET socket, bool isHttps) {
    auto connection = std::make_shared<core::ConnectionContext>(socket, isHttps);

    sockaddr_in addr{};
    int addrLen = sizeof(addr);
    if (getpeername(socket, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        connection->SetRemoteAddress(std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port)));
    }

    if (isHttps && m_schannelContext) {
        auto tls = std::make_unique<security::TlsConnection>(*m_schannelContext);
        connection->SetTlsConnection(std::move(tls));
        connection->SetState(core::ConnectionState::TlsHandshaking);
    }

    return connection;
}

void HttpServer::CloseConnection(core::ConnectionContext* connection) {
    if (connection) {
        connection->Close();
    }
}

void HttpServer::RemoveConnection(SOCKET socket) {
    std::lock_guard<std::mutex> lock(m_connectionsMutex);
    auto it = m_connections.find(socket);
    if (it != m_connections.end()) {
        m_connections.erase(it);
        m_activeConnections.fetch_sub(1, std::memory_order_relaxed);
    }
}

void HttpServer::WaitForConnections(std::chrono::seconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;

    while (m_activeConnections.load() > 0) {
        if (std::chrono::steady_clock::now() > deadline) {
            utils::Logger::Warning("Timeout waiting for connections to close, forcing shutdown");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

} // namespace http_server
