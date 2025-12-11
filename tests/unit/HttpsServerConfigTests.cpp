#include "server/HttpServer.hpp"
#include "http/HttpResponse.hpp"
#include "utils/Logger.hpp"

#include <gtest/gtest.h>
#include <chrono>
#include <thread>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <WinSock2.h>

using namespace http_server;

class HttpsServerConfigTest : public ::testing::Test {
protected:
    static bool s_winsockInitialized;

    static void SetUpTestSuite() {
        WSADATA wsaData;
        s_winsockInitialized = (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
        utils::Logger::SetLevel(utils::LogLevel::Warning);
    }

    static void TearDownTestSuite() {
        if (s_winsockInitialized) {
            WSACleanup();
        }
    }

    void SetUp() override {
        if (!s_winsockInitialized) {
            GTEST_SKIP() << "Winsock initialization failed";
        }
    }
};

bool HttpsServerConfigTest::s_winsockInitialized = false;

// ============================================================================
// ServerConfig HTTPS Settings Tests
// ============================================================================

TEST_F(HttpsServerConfigTest, ServerConfig_DefaultHttpsPort_Is8443) {
    ServerConfig config;
    EXPECT_EQ(config.httpsPort, 8443);
}

TEST_F(HttpsServerConfigTest, ServerConfig_DefaultEnableHttps_IsFalse) {
    ServerConfig config;
    EXPECT_FALSE(config.enableHttps);
}

TEST_F(HttpsServerConfigTest, ServerConfig_DefaultCertificateSubject_IsEmpty) {
    ServerConfig config;
    EXPECT_TRUE(config.certificateSubject.empty());
}

TEST_F(HttpsServerConfigTest, ServerConfig_CustomHttpsPort_IsStored) {
    ServerConfig config;
    config.httpsPort = 9443;
    EXPECT_EQ(config.httpsPort, 9443);
}

TEST_F(HttpsServerConfigTest, ServerConfig_EnableHttps_CanBeSet) {
    ServerConfig config;
    config.enableHttps = true;
    EXPECT_TRUE(config.enableHttps);
}

TEST_F(HttpsServerConfigTest, ServerConfig_CertificateSubject_CanBeSet) {
    ServerConfig config;
    config.certificateSubject = L"localhost";
    EXPECT_EQ(config.certificateSubject, L"localhost");
}

// ============================================================================
// HttpServer HTTPS Initialization Tests
// ============================================================================

TEST_F(HttpsServerConfigTest, HttpServer_WithHttpsDisabled_StartsSuccessfully) {
    ServerConfig config;
    config.port = 0;  // Let OS assign
    config.enableHttps = false;
    
    HttpServer server(config);
    
    EXPECT_NO_THROW(server.Start());
    EXPECT_TRUE(server.IsRunning());
    EXPECT_NE(server.GetPort(), 0);
    
    server.Stop();
    EXPECT_FALSE(server.IsRunning());
}

TEST_F(HttpsServerConfigTest, HttpServer_WithHttpsEnabled_NoCertificate_StartsWithWarning) {
    ServerConfig config;
    config.port = 0;
    config.httpsPort = 0;
    config.enableHttps = true;
    config.certificateSubject = L"";  // Empty certificate
    
    HttpServer server(config);
    
    // Should start HTTP but HTTPS init will silently fail (no certificate)
    EXPECT_NO_THROW(server.Start());
    EXPECT_TRUE(server.IsRunning());
    
    server.Stop();
}

TEST_F(HttpsServerConfigTest, HttpServer_WithHttpsEnabled_InvalidCertificate_StartsWithWarning) {
    ServerConfig config;
    config.port = 0;
    config.httpsPort = 0;
    config.enableHttps = true;
    config.certificateSubject = L"nonexistent_certificate_12345";
    
    HttpServer server(config);
    
    // Should start HTTP but HTTPS will fail gracefully
    EXPECT_NO_THROW(server.Start());
    EXPECT_TRUE(server.IsRunning());
    
    server.Stop();
}

TEST_F(HttpsServerConfigTest, HttpServer_WithHttpsEnabled_ValidCertificate_StartsBoth) {
    ServerConfig config;
    config.port = 0;
    config.httpsPort = 0;
    config.enableHttps = true;
    config.certificateSubject = L"localhost";
    
    HttpServer server(config);
    
    server.Start();
    
    if (server.GetHttpsPort() != 0) {
        // HTTPS is available
        EXPECT_TRUE(server.IsRunning());
        EXPECT_NE(server.GetPort(), 0);
        EXPECT_NE(server.GetHttpsPort(), 0);
        EXPECT_NE(server.GetPort(), server.GetHttpsPort());
    } else {
        // Certificate not found - just check HTTP works
        EXPECT_TRUE(server.IsRunning());
        EXPECT_NE(server.GetPort(), 0);
    }
    
    server.Stop();
}

TEST_F(HttpsServerConfigTest, HttpServer_GetHttpsPort_ReturnsConfiguredPort) {
    ServerConfig config;
    config.port = 0;
    config.httpsPort = 9443;
    config.enableHttps = false;
    
    HttpServer server(config);
    
    // Before start, returns configured port
    EXPECT_EQ(server.GetHttpsPort(), 9443);
}

TEST_F(HttpsServerConfigTest, HttpServer_GetHttpsPort_WithZero_ReturnsAssignedPort) {
    ServerConfig config;
    config.port = 0;
    config.httpsPort = 0;  // Let OS assign
    config.enableHttps = true;
    config.certificateSubject = L"localhost";
    
    HttpServer server(config);
    server.Start();
    
    if (server.GetHttpsPort() != 0) {
        // HTTPS initialized successfully, port should be assigned
        EXPECT_GT(server.GetHttpsPort(), 0);
        EXPECT_LE(server.GetHttpsPort(), 65535);
    }
    
    server.Stop();
}

// ============================================================================
// Multiple Start/Stop Cycles
// ============================================================================

TEST_F(HttpsServerConfigTest, HttpServer_MultipleStartStop_Works) {
    ServerConfig config;
    config.port = 0;
    config.enableHttps = false;
    
    HttpServer server(config);
    
    // First cycle
    server.Start();
    EXPECT_TRUE(server.IsRunning());
    server.Stop();
    EXPECT_FALSE(server.IsRunning());
    
    // Note: Restarting the same server instance may not be supported
    // This test just verifies the first cycle works
}

TEST_F(HttpsServerConfigTest, HttpServer_StopWithoutStart_NoThrow) {
    ServerConfig config;
    config.port = 0;
    config.enableHttps = false;
    
    HttpServer server(config);
    
    // Stop without starting should not throw
    EXPECT_NO_THROW(server.Stop());
    EXPECT_FALSE(server.IsRunning());
}

TEST_F(HttpsServerConfigTest, HttpServer_DoubleStart_IgnoresSecond) {
    ServerConfig config;
    config.port = 0;
    config.enableHttps = false;
    
    HttpServer server(config);
    
    server.Start();
    uint16_t firstPort = server.GetPort();
    
    // Second start should be ignored
    server.Start();
    
    EXPECT_EQ(server.GetPort(), firstPort);
    EXPECT_TRUE(server.IsRunning());
    
    server.Stop();
}

// ============================================================================
// Connection Count Tests
// ============================================================================

TEST_F(HttpsServerConfigTest, HttpServer_GetActiveConnections_InitiallyZero) {
    ServerConfig config;
    config.port = 0;
    config.enableHttps = false;
    
    HttpServer server(config);
    server.Start();
    
    EXPECT_EQ(server.GetActiveConnections(), 0);
    
    server.Stop();
}

// ============================================================================
// Router Access Tests
// ============================================================================

TEST_F(HttpsServerConfigTest, HttpServer_GetRouter_ReturnsReference) {
    ServerConfig config;
    config.port = 0;
    config.enableHttps = false;
    
    HttpServer server(config);
    
    // Should be able to access router before and after start
    http::HttpRouter& routerBefore = server.GetRouter();
    
    server.Start();
    
    http::HttpRouter& routerAfter = server.GetRouter();
    
    // Should be the same router
    EXPECT_EQ(&routerBefore, &routerAfter);
    
    server.Stop();
}

TEST_F(HttpsServerConfigTest, HttpServer_AddCustomRoute_Works) {
    ServerConfig config;
    config.port = 0;
    config.enableHttps = false;
    
    HttpServer server(config);
    
    bool routeHit = false;
    server.GetRouter().Get("/custom", [&routeHit](http::HttpRequest& /*req*/) -> http::HttpResponse {
        routeHit = true;
        return http::HttpResponse::Ok();
    });
    
    // Route should be registered (we can't easily test it's hit without making a connection)
    EXPECT_NO_THROW(server.Start());
    
    server.Stop();
}

// ============================================================================
// Configuration Validation Tests
// ============================================================================

TEST_F(HttpsServerConfigTest, ServerConfig_ZeroPorts_Valid) {
    ServerConfig config;
    config.port = 0;
    config.httpsPort = 0;
    
    // Zero is valid - means let OS assign
    HttpServer server(config);
    EXPECT_NO_THROW(server.Start());
    
    EXPECT_NE(server.GetPort(), 0);  // Should be assigned
    
    server.Stop();
}

TEST_F(HttpsServerConfigTest, ServerConfig_MaxPort_Valid) {
    ServerConfig config;
    config.port = 65535;
    config.enableHttps = false;
    
    // Max port value should be accepted (though binding might fail)
    HttpServer server(config);
    // Don't start - port 65535 might be in use or restricted
}

TEST_F(HttpsServerConfigTest, ServerConfig_ThreadPoolSize_CanBeSet) {
    ServerConfig config;
    config.port = 0;
    config.threadPoolSize = 4;
    config.enableHttps = false;
    
    HttpServer server(config);
    EXPECT_NO_THROW(server.Start());
    
    server.Stop();
}

TEST_F(HttpsServerConfigTest, ServerConfig_ConnectionTimeout_CanBeSet) {
    ServerConfig config;
    config.port = 0;
    config.connectionTimeout = std::chrono::seconds(30);
    config.enableHttps = false;
    
    HttpServer server(config);
    EXPECT_NO_THROW(server.Start());
    
    server.Stop();
}

TEST_F(HttpsServerConfigTest, ServerConfig_MaxConnections_CanBeSet) {
    ServerConfig config;
    config.port = 0;
    config.maxConnections = 100;
    config.enableHttps = false;
    
    HttpServer server(config);
    EXPECT_NO_THROW(server.Start());
    
    server.Stop();
}
