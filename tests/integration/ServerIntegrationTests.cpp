#include "server/HttpServer.hpp"
#include "utils/Logger.hpp"

#include <gtest/gtest.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <sstream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

using namespace http_server;

struct HttpTestResponse {
    int statusCode = 0;
    std::string statusText;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

class TestClient {
public:
    TestClient(const std::string& host, uint16_t port)
        : m_host(host), m_port(port), m_socket(INVALID_SOCKET) {
    }

    ~TestClient() {
        Disconnect();
    }

    bool Connect() {
        m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_socket == INVALID_SOCKET) {
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(m_port);
        inet_pton(AF_INET, m_host.c_str(), &addr.sin_addr);

        if (connect(m_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
            return false;
        }

        // Set timeout
        DWORD timeout = 5000;
        setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

        return true;
    }

    void Disconnect() {
        if (m_socket != INVALID_SOCKET) {
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
    }

    HttpTestResponse SendRequest(const std::string& method, const std::string& path,
                                  const std::string& body = "") {
        HttpTestResponse response;

        if (m_socket == INVALID_SOCKET && !Connect()) {
            throw std::runtime_error("Failed to connect");
        }

        // Build request
        std::ostringstream request;
        request << method << " " << path << " HTTP/1.1\r\n";
        request << "Host: " << m_host << ":" << m_port << "\r\n";

        if (!body.empty()) {
            request << "Content-Type: application/json\r\n";
            request << "Content-Length: " << body.size() << "\r\n";
        }

        request << "Connection: close\r\n";
        request << "\r\n";

        if (!body.empty()) {
            request << body;
        }

        std::string requestStr = request.str();

        // Send request
        int sent = send(m_socket, requestStr.c_str(), static_cast<int>(requestStr.size()), 0);
        if (sent == SOCKET_ERROR) {
            throw std::runtime_error("Failed to send request");
        }

        // Receive response
        std::string responseStr;
        char buffer[4096];
        int received;

        while ((received = recv(m_socket, buffer, sizeof(buffer), 0)) > 0) {
            responseStr.append(buffer, received);
        }

        // Parse response
        ParseResponse(responseStr, response);

        Disconnect();
        return response;
    }

private:
    void ParseResponse(const std::string& raw, HttpTestResponse& response) {
        // Parse status line
        auto lineEnd = raw.find("\r\n");
        if (lineEnd == std::string::npos) {
            return;
        }

        std::string statusLine = raw.substr(0, lineEnd);
        auto firstSpace = statusLine.find(' ');
        auto secondSpace = statusLine.find(' ', firstSpace + 1);

        if (firstSpace != std::string::npos && secondSpace != std::string::npos) {
            response.statusCode = std::stoi(statusLine.substr(firstSpace + 1, secondSpace - firstSpace - 1));
            response.statusText = statusLine.substr(secondSpace + 1);
        }

        // Find body
        auto bodyStart = raw.find("\r\n\r\n");
        if (bodyStart != std::string::npos) {
            response.body = raw.substr(bodyStart + 4);
        }
    }

    std::string m_host;
    uint16_t m_port;
    SOCKET m_socket;
};

// Test fixture for server integration tests
class ServerIntegrationTest : public ::testing::Test {
protected:
    static std::unique_ptr<HttpServer> s_server;
    static uint16_t s_port;

    static void SetUpTestSuite() {
        // Initialize Winsock
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        utils::Logger::SetLevel(utils::LogLevel::Warning);  // Reduce noise

        ServerConfig config;
        config.port = 0;  // Let OS assign port
        config.serverVersion = "1.0-test";

        s_server = std::make_unique<HttpServer>(config);
        s_server->Start();
        s_port = s_server->GetPort();

        // Give server time to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    static void TearDownTestSuite() {
        if (s_server) {
            s_server->Stop();
            s_server.reset();
        }
        WSACleanup();
    }

    TestClient CreateClient() {
        return TestClient("127.0.0.1", s_port);
    }
};

// Static member definitions
std::unique_ptr<HttpServer> ServerIntegrationTest::s_server;
uint16_t ServerIntegrationTest::s_port = 0;

TEST_F(ServerIntegrationTest, GetInfoReturnsValidJson) {
    auto client = CreateClient();
    auto response = client.SendRequest("GET", "/info");

    EXPECT_EQ(response.statusCode, 200);
    EXPECT_FALSE(response.body.empty());

    // Verify JSON structure
    auto json = nlohmann::json::parse(response.body);
    EXPECT_TRUE(json.contains("version"));
    EXPECT_TRUE(json.contains("platform"));
    EXPECT_TRUE(json.contains("started"));
    EXPECT_TRUE(json.contains("connections"));
}

TEST_F(ServerIntegrationTest, PostDataReturns201) {
    auto client = CreateClient();
    auto response = client.SendRequest("POST", "/data", R"({"name": "test"})");

    EXPECT_EQ(response.statusCode, 201);
}

TEST_F(ServerIntegrationTest, GetDataReturnsStoredValue) {
    // First store data
    auto client1 = CreateClient();
    auto postResponse = client1.SendRequest("POST", "/data", R"({"testkey": "testvalue"})");
    ASSERT_EQ(postResponse.statusCode, 201);

    // Then retrieve it
    auto client2 = CreateClient();
    auto getResponse = client2.SendRequest("GET", "/data/testkey");

    EXPECT_EQ(getResponse.statusCode, 200);
    auto json = nlohmann::json::parse(getResponse.body);
    EXPECT_EQ(json["testkey"], "testvalue");
}

TEST_F(ServerIntegrationTest, GetMissingDataReturns404) {
    auto client = CreateClient();
    auto response = client.SendRequest("GET", "/data/nonexistent_key_12345");

    EXPECT_EQ(response.statusCode, 404);
}

TEST_F(ServerIntegrationTest, UnknownEndpointReturns404) {
    auto client = CreateClient();
    auto response = client.SendRequest("GET", "/unknown/endpoint");

    EXPECT_EQ(response.statusCode, 404);
}

TEST_F(ServerIntegrationTest, InvalidMethodReturns405Or404) {
    auto client = CreateClient();

    // Try to POST to /info (which only accepts GET)
    auto response = client.SendRequest("POST", "/info", "{}");

    // Actually /info allows GET only, so we should get 404 for POST
    // Let's check /data which allows both GET and POST
    // A PUT would be method not allowed
    EXPECT_TRUE(response.statusCode == 404 || response.statusCode == 405);
}

TEST_F(ServerIntegrationTest, MalformedJsonReturns400) {
    auto client = CreateClient();
    auto response = client.SendRequest("POST", "/data", "not valid json");

    EXPECT_EQ(response.statusCode, 400);
}

TEST_F(ServerIntegrationTest, MultipleRequests) {
    // Test multiple sequential requests work
    for (int i = 0; i < 5; ++i) {
        auto client = CreateClient();
        auto response = client.SendRequest("GET", "/info");
        EXPECT_EQ(response.statusCode, 200);
    }
}

// ============================================================================
// HTTPS Test Client using Schannel
// ============================================================================

class TlsTestClient {
public:
    TlsTestClient(const std::string& host, uint16_t port)
        : m_host(host), m_port(port), m_socket(INVALID_SOCKET), m_contextInitialized(false) {
        SecInvalidateHandle(&m_credentials);
        SecInvalidateHandle(&m_context);
    }

    ~TlsTestClient() {
        Disconnect();
        ReleaseCredentials();
    }

    bool InitializeCredentials() {
        SCHANNEL_CRED cred = {};
        cred.dwVersion = SCHANNEL_CRED_VERSION;
        cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | 
                       SCH_CRED_MANUAL_CRED_VALIDATION |  // Skip cert validation for testing
                       SCH_CRED_NO_SERVERNAME_CHECK;
        cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;

        SECURITY_STATUS status = AcquireCredentialsHandleW(
            nullptr,
            const_cast<LPWSTR>(UNISP_NAME_W),
            SECPKG_CRED_OUTBOUND,
            nullptr,
            &cred,
            nullptr,
            nullptr,
            &m_credentials,
            nullptr
        );

        return status == SEC_E_OK;
    }

    void ReleaseCredentials() {
        if (SecIsValidHandle(&m_credentials)) {
            FreeCredentialsHandle(&m_credentials);
            SecInvalidateHandle(&m_credentials);
        }
        if (SecIsValidHandle(&m_context)) {
            DeleteSecurityContext(&m_context);
            SecInvalidateHandle(&m_context);
        }
    }

    bool Connect() {
        m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_socket == INVALID_SOCKET) {
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(m_port);
        inet_pton(AF_INET, m_host.c_str(), &addr.sin_addr);

        if (connect(m_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
            return false;
        }

        // Set timeout
        DWORD timeout = 10000;  // 10 seconds for TLS handshake
        setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

        return true;
    }

    bool DoHandshake() {
        std::wstring wideHost(m_host.begin(), m_host.end());

        // Initial token buffers
        SecBuffer outBuffers[1];
        outBuffers[0].pvBuffer = nullptr;
        outBuffers[0].BufferType = SECBUFFER_TOKEN;
        outBuffers[0].cbBuffer = 0;

        SecBufferDesc outBufferDesc;
        outBufferDesc.cBuffers = 1;
        outBufferDesc.pBuffers = outBuffers;
        outBufferDesc.ulVersion = SECBUFFER_VERSION;

        DWORD contextReq = ISC_REQ_SEQUENCE_DETECT |
                           ISC_REQ_REPLAY_DETECT |
                           ISC_REQ_CONFIDENTIALITY |
                           ISC_REQ_ALLOCATE_MEMORY |
                           ISC_REQ_STREAM;

        DWORD contextAttr = 0;

        // First call - initiate handshake
        SECURITY_STATUS status = InitializeSecurityContextW(
            &m_credentials,
            nullptr,  // First call
            const_cast<LPWSTR>(wideHost.c_str()),
            contextReq,
            0,
            0,
            nullptr,
            0,
            &m_context,
            &outBufferDesc,
            &contextAttr,
            nullptr
        );

        if (status != SEC_I_CONTINUE_NEEDED) {
            return false;
        }

        // Send initial handshake data
        if (outBuffers[0].cbBuffer > 0 && outBuffers[0].pvBuffer) {
            int sent = send(m_socket, static_cast<char*>(outBuffers[0].pvBuffer), outBuffers[0].cbBuffer, 0);
            FreeContextBuffer(outBuffers[0].pvBuffer);
            if (sent == SOCKET_ERROR) {
                return false;
            }
        }

        // Continue handshake loop
        std::vector<char> buffer(16384);
        int totalReceived = 0;

        while (true) {
            // Receive server response
            int received = recv(m_socket, buffer.data() + totalReceived, 
                              static_cast<int>(buffer.size()) - totalReceived, 0);
            if (received <= 0) {
                m_lastError = (received == 0) ? 0xDEAD0001 : static_cast<SECURITY_STATUS>(WSAGetLastError());
                return false;
            }
            totalReceived += received;

            // Process received data
            SecBuffer inBuffers[2];
            inBuffers[0].pvBuffer = buffer.data();
            inBuffers[0].cbBuffer = totalReceived;
            inBuffers[0].BufferType = SECBUFFER_TOKEN;
            inBuffers[1].pvBuffer = nullptr;
            inBuffers[1].cbBuffer = 0;
            inBuffers[1].BufferType = SECBUFFER_EMPTY;

            SecBufferDesc inBufferDesc;
            inBufferDesc.cBuffers = 2;
            inBufferDesc.pBuffers = inBuffers;
            inBufferDesc.ulVersion = SECBUFFER_VERSION;

            outBuffers[0].pvBuffer = nullptr;
            outBuffers[0].BufferType = SECBUFFER_TOKEN;
            outBuffers[0].cbBuffer = 0;

            status = InitializeSecurityContextW(
                &m_credentials,
                &m_context,
                nullptr,
                contextReq,
                0,
                0,
                &inBufferDesc,
                0,
                nullptr,
                &outBufferDesc,
                &contextAttr,
                nullptr
            );

            // Send any output token
            if (outBuffers[0].cbBuffer > 0 && outBuffers[0].pvBuffer) {
                int sent = send(m_socket, static_cast<char*>(outBuffers[0].pvBuffer), 
                              outBuffers[0].cbBuffer, 0);
                FreeContextBuffer(outBuffers[0].pvBuffer);
                if (sent == SOCKET_ERROR) {
                    return false;
                }
            }

            if (status == SEC_E_OK) {
                m_contextInitialized = true;
                
                // Query stream sizes for encryption/decryption
                status = QueryContextAttributesW(&m_context, SECPKG_ATTR_STREAM_SIZES, &m_streamSizes);
                return status == SEC_E_OK;
            }

            if (status == SEC_I_CONTINUE_NEEDED) {
                // Handle extra data
                if (inBuffers[1].BufferType == SECBUFFER_EXTRA && inBuffers[1].cbBuffer > 0) {
                    memmove(buffer.data(), buffer.data() + totalReceived - inBuffers[1].cbBuffer, 
                           inBuffers[1].cbBuffer);
                    totalReceived = inBuffers[1].cbBuffer;
                } else {
                    totalReceived = 0;
                }
                continue;
            }

            if (status == SEC_E_INCOMPLETE_MESSAGE) {
                continue;  // Need more data
            }

            // Handshake failed - store status for debugging
            m_lastError = status;
            return false;
        }
    }

    SECURITY_STATUS GetLastError() const { return m_lastError; }

    void Disconnect() {
        if (m_socket != INVALID_SOCKET) {
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
        m_contextInitialized = false;
    }

    std::vector<char> Encrypt(const std::string& data) {
        std::vector<char> result;
        if (!m_contextInitialized) return result;

        size_t messageSize = data.size();
        size_t bufferSize = m_streamSizes.cbHeader + messageSize + m_streamSizes.cbTrailer;
        std::vector<char> buffer(bufferSize);

        // Copy message after header
        memcpy(buffer.data() + m_streamSizes.cbHeader, data.data(), messageSize);

        SecBuffer buffers[4];
        buffers[0].pvBuffer = buffer.data();
        buffers[0].cbBuffer = m_streamSizes.cbHeader;
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

        buffers[1].pvBuffer = buffer.data() + m_streamSizes.cbHeader;
        buffers[1].cbBuffer = static_cast<ULONG>(messageSize);
        buffers[1].BufferType = SECBUFFER_DATA;

        buffers[2].pvBuffer = buffer.data() + m_streamSizes.cbHeader + messageSize;
        buffers[2].cbBuffer = m_streamSizes.cbTrailer;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

        buffers[3].pvBuffer = nullptr;
        buffers[3].cbBuffer = 0;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc bufferDesc;
        bufferDesc.ulVersion = SECBUFFER_VERSION;
        bufferDesc.cBuffers = 4;
        bufferDesc.pBuffers = buffers;

        SECURITY_STATUS status = EncryptMessage(&m_context, 0, &bufferDesc, 0);
        if (status != SEC_E_OK) {
            return result;
        }

        size_t totalSize = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        result.assign(buffer.begin(), buffer.begin() + totalSize);
        return result;
    }

    std::string Decrypt(const std::vector<char>& data) {
        if (!m_contextInitialized || data.empty()) return "";

        std::vector<char> buffer = data;

        SecBuffer buffers[4];
        buffers[0].pvBuffer = buffer.data();
        buffers[0].cbBuffer = static_cast<ULONG>(buffer.size());
        buffers[0].BufferType = SECBUFFER_DATA;
        buffers[1].BufferType = SECBUFFER_EMPTY;
        buffers[2].BufferType = SECBUFFER_EMPTY;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc bufferDesc;
        bufferDesc.ulVersion = SECBUFFER_VERSION;
        bufferDesc.cBuffers = 4;
        bufferDesc.pBuffers = buffers;

        SECURITY_STATUS status = DecryptMessage(&m_context, &bufferDesc, 0, nullptr);
        if (status != SEC_E_OK) {
            return "";
        }

        // Find the data buffer
        for (int i = 0; i < 4; ++i) {
            if (buffers[i].BufferType == SECBUFFER_DATA) {
                return std::string(static_cast<char*>(buffers[i].pvBuffer), buffers[i].cbBuffer);
            }
        }

        return "";
    }

    HttpTestResponse SendRequest(const std::string& method, const std::string& path,
                                  const std::string& body = "") {
        HttpTestResponse response;

        // Build HTTP request
        std::ostringstream request;
        request << method << " " << path << " HTTP/1.1\r\n";
        request << "Host: " << m_host << ":" << m_port << "\r\n";

        if (!body.empty()) {
            request << "Content-Type: application/json\r\n";
            request << "Content-Length: " << body.size() << "\r\n";
        }

        request << "Connection: close\r\n";
        request << "\r\n";

        if (!body.empty()) {
            request << body;
        }

        std::string requestStr = request.str();

        // Encrypt and send
        auto encrypted = Encrypt(requestStr);
        if (encrypted.empty()) {
            throw std::runtime_error("Failed to encrypt request");
        }

        int sent = send(m_socket, encrypted.data(), static_cast<int>(encrypted.size()), 0);
        if (sent == SOCKET_ERROR) {
            throw std::runtime_error("Failed to send encrypted request");
        }

        // Receive and decrypt response
        std::vector<char> encryptedResponse;
        char recvBuffer[8192];
        int received;

        while ((received = recv(m_socket, recvBuffer, sizeof(recvBuffer), 0)) > 0) {
            encryptedResponse.insert(encryptedResponse.end(), recvBuffer, recvBuffer + received);
        }

        std::string decrypted = Decrypt(encryptedResponse);
        ParseResponse(decrypted, response);

        return response;
    }

private:
    void ParseResponse(const std::string& raw, HttpTestResponse& response) {
        if (raw.empty()) return;

        auto lineEnd = raw.find("\r\n");
        if (lineEnd == std::string::npos) return;

        std::string statusLine = raw.substr(0, lineEnd);
        auto firstSpace = statusLine.find(' ');
        auto secondSpace = statusLine.find(' ', firstSpace + 1);

        if (firstSpace != std::string::npos && secondSpace != std::string::npos) {
            response.statusCode = std::stoi(statusLine.substr(firstSpace + 1, secondSpace - firstSpace - 1));
            response.statusText = statusLine.substr(secondSpace + 1);
        }

        auto bodyStart = raw.find("\r\n\r\n");
        if (bodyStart != std::string::npos) {
            response.body = raw.substr(bodyStart + 4);
        }
    }

    std::string m_host;
    uint16_t m_port;
    SOCKET m_socket;
    CredHandle m_credentials;
    CtxtHandle m_context;
    SecPkgContext_StreamSizes m_streamSizes;
    bool m_contextInitialized;
    SECURITY_STATUS m_lastError = 0;
};

// ============================================================================
// HTTPS Integration Tests
// ============================================================================

class HttpsServerIntegrationTest : public ::testing::Test {
protected:
    static std::unique_ptr<HttpServer> s_server;
    static uint16_t s_httpsPort;
    static bool s_httpsAvailable;

    static void SetUpTestSuite() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        utils::Logger::SetLevel(utils::LogLevel::Warning);  // Reduce test noise

        ServerConfig config;
        config.port = 0;
        config.httpsPort = 0;  // Let OS assign port
        config.enableHttps = true;
        // Use localhost certificate - needs to be installed in certificate store
        config.certificateSubject = L"localhost";
        config.serverVersion = "1.0-https-test";

        s_server = std::make_unique<HttpServer>(config);
        
        try {
            s_server->Start();
            s_httpsPort = s_server->GetHttpsPort();
            s_httpsAvailable = (s_httpsPort != 0);
        } catch (...) {
            s_httpsAvailable = false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    static void TearDownTestSuite() {
        if (s_server) {
            s_server->Stop();
            s_server.reset();
        }
        WSACleanup();
    }

    void SetUp() override {
        if (!s_httpsAvailable) {
            GTEST_SKIP() << "HTTPS not available (certificate not found or Schannel init failed)";
        }
    }

    TlsTestClient CreateTlsClient() {
        return TlsTestClient("127.0.0.1", s_httpsPort);
    }
};

std::unique_ptr<HttpServer> HttpsServerIntegrationTest::s_server;
uint16_t HttpsServerIntegrationTest::s_httpsPort = 0;
bool HttpsServerIntegrationTest::s_httpsAvailable = false;

TEST_F(HttpsServerIntegrationTest, TlsHandshakeSucceeds) {
    auto client = CreateTlsClient();
    ASSERT_TRUE(client.InitializeCredentials()) << "Failed to initialize TLS credentials";
    ASSERT_TRUE(client.Connect()) << "Failed to connect to HTTPS server";
    bool handshakeResult = client.DoHandshake();
    EXPECT_TRUE(handshakeResult) << "TLS handshake failed with status: 0x" << std::hex << client.GetLastError();
}

TEST_F(HttpsServerIntegrationTest, HttpsGetInfoReturnsValidJson) {
    auto client = CreateTlsClient();
    ASSERT_TRUE(client.InitializeCredentials());
    ASSERT_TRUE(client.Connect());
    ASSERT_TRUE(client.DoHandshake());

    auto response = client.SendRequest("GET", "/info");

    EXPECT_EQ(response.statusCode, 200);
    EXPECT_FALSE(response.body.empty());

    auto json = nlohmann::json::parse(response.body);
    EXPECT_TRUE(json.contains("version"));
    EXPECT_TRUE(json.contains("platform"));
}

TEST_F(HttpsServerIntegrationTest, HttpsPostDataReturns201) {
    auto client = CreateTlsClient();
    ASSERT_TRUE(client.InitializeCredentials());
    ASSERT_TRUE(client.Connect());
    ASSERT_TRUE(client.DoHandshake());

    auto response = client.SendRequest("POST", "/data", R"({"https_key": "https_value"})");

    EXPECT_EQ(response.statusCode, 201);
}

TEST_F(HttpsServerIntegrationTest, HttpsGetDataReturnsStoredValue) {
    // Post data via HTTPS
    {
        auto client = CreateTlsClient();
        ASSERT_TRUE(client.InitializeCredentials());
        ASSERT_TRUE(client.Connect());
        ASSERT_TRUE(client.DoHandshake());

        auto response = client.SendRequest("POST", "/data", R"({"https_test_key": "https_test_value"})");
        ASSERT_EQ(response.statusCode, 201);
    }

    // Get data via HTTPS
    {
        auto client = CreateTlsClient();
        ASSERT_TRUE(client.InitializeCredentials());
        ASSERT_TRUE(client.Connect());
        ASSERT_TRUE(client.DoHandshake());

        auto response = client.SendRequest("GET", "/data/https_test_key");
        EXPECT_EQ(response.statusCode, 200);

        auto json = nlohmann::json::parse(response.body);
        EXPECT_EQ(json["https_test_key"], "https_test_value");
    }
}

TEST_F(HttpsServerIntegrationTest, HttpsUnknownEndpointReturns404) {
    auto client = CreateTlsClient();
    ASSERT_TRUE(client.InitializeCredentials());
    ASSERT_TRUE(client.Connect());
    ASSERT_TRUE(client.DoHandshake());

    auto response = client.SendRequest("GET", "/nonexistent");

    EXPECT_EQ(response.statusCode, 404);
}

TEST_F(HttpsServerIntegrationTest, HttpsMalformedJsonReturns400) {
    auto client = CreateTlsClient();
    ASSERT_TRUE(client.InitializeCredentials());
    ASSERT_TRUE(client.Connect());
    ASSERT_TRUE(client.DoHandshake());

    auto response = client.SendRequest("POST", "/data", "invalid json {{{");

    EXPECT_EQ(response.statusCode, 400);
}

TEST_F(HttpsServerIntegrationTest, MultipleHttpsRequests) {
    for (int i = 0; i < 3; ++i) {
        auto client = CreateTlsClient();
        ASSERT_TRUE(client.InitializeCredentials());
        ASSERT_TRUE(client.Connect());
        ASSERT_TRUE(client.DoHandshake());

        auto response = client.SendRequest("GET", "/info");
        EXPECT_EQ(response.statusCode, 200);
    }
}
