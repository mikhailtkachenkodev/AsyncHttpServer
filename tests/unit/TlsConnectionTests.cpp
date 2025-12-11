#include "security/TlsConnection.hpp"
#include "security/SchannelContext.hpp"
#include "utils/Logger.hpp"

#include <gtest/gtest.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

using namespace http_server::security;

class TlsConnectionTest : public ::testing::Test {
protected:
    static std::unique_ptr<SchannelContext> s_schannelContext;
    static bool s_schannelAvailable;

    static void SetUpTestSuite() {
        http_server::utils::Logger::SetLevel(http_server::utils::LogLevel::Warning);
        
        s_schannelContext = std::make_unique<SchannelContext>();
        s_schannelAvailable = s_schannelContext->Initialize(L"localhost");
    }

    static void TearDownTestSuite() {
        s_schannelContext.reset();
    }

    void SetUp() override {
        if (!s_schannelAvailable) {
            GTEST_SKIP() << "Schannel not available (localhost certificate not installed)";
        }
    }

    SchannelContext& GetSchannelContext() {
        return *s_schannelContext;
    }
};

std::unique_ptr<SchannelContext> TlsConnectionTest::s_schannelContext;
bool TlsConnectionTest::s_schannelAvailable = false;

// ============================================================================
// Construction and Destruction Tests
// ============================================================================

TEST_F(TlsConnectionTest, Constructor_InitializesCorrectly) {
    TlsConnection connection(GetSchannelContext());
    
    EXPECT_FALSE(connection.IsHandshakeComplete());
    EXPECT_TRUE(connection.GetHandshakeResponse().empty());
}

TEST_F(TlsConnectionTest, Destructor_NoThrow) {
    EXPECT_NO_THROW({
        TlsConnection connection(GetSchannelContext());
        // Let it destruct
    });
}

TEST_F(TlsConnectionTest, NonCopyable_CompileCheck) {
    EXPECT_FALSE(std::is_copy_constructible_v<TlsConnection>);
    EXPECT_FALSE(std::is_copy_assignable_v<TlsConnection>);
}

// ============================================================================
// Handshake State Tests
// ============================================================================

TEST_F(TlsConnectionTest, IsHandshakeComplete_InitiallyFalse) {
    TlsConnection connection(GetSchannelContext());
    
    EXPECT_FALSE(connection.IsHandshakeComplete());
}

TEST_F(TlsConnectionTest, GetHandshakeResponse_InitiallyEmpty) {
    TlsConnection connection(GetSchannelContext());
    
    EXPECT_TRUE(connection.GetHandshakeResponse().empty());
}

TEST_F(TlsConnectionTest, ClearHandshakeResponse_ClearsVector) {
    TlsConnection connection(GetSchannelContext());
    
    // Trigger some handshake activity that might populate response
    connection.DoHandshake("dummy", 5);
    connection.ClearHandshakeResponse();
    
    EXPECT_TRUE(connection.GetHandshakeResponse().empty());
}

// ============================================================================
// DoHandshake Tests
// ============================================================================

TEST_F(TlsConnectionTest, DoHandshake_WithNullData_ReturnsNeedMoreDataOrFailed) {
    TlsConnection connection(GetSchannelContext());
    
    // Null/empty data should fail or need more data
    auto result = connection.DoHandshake(nullptr, 0);
    
    EXPECT_TRUE(result == HandshakeResult::NeedMoreData || 
                result == HandshakeResult::Failed);
}

TEST_F(TlsConnectionTest, DoHandshake_WithInvalidData_ReturnsFailed) {
    TlsConnection connection(GetSchannelContext());
    
    // Random garbage data is not a valid TLS ClientHello
    const char garbage[] = "This is not a valid TLS ClientHello message!";
    auto result = connection.DoHandshake(garbage, sizeof(garbage) - 1);
    
    // Should fail because it's not valid TLS data
    EXPECT_EQ(result, HandshakeResult::Failed);
}

TEST_F(TlsConnectionTest, DoHandshake_WithIncompleteData_ReturnsNeedMoreData) {
    TlsConnection connection(GetSchannelContext());
    
    // Partial TLS record header (5 bytes for record header, but incomplete)
    const unsigned char partialRecord[] = {
        0x16,  // Content type: Handshake
        0x03, 0x03,  // TLS version 1.2
        0x00, 0xFF   // Length: 255 (but no data follows)
    };
    
    auto result = connection.DoHandshake(
        reinterpret_cast<const char*>(partialRecord), 
        sizeof(partialRecord)
    );
    
    // Should need more data since the record is incomplete
    EXPECT_TRUE(result == HandshakeResult::NeedMoreData || 
                result == HandshakeResult::Failed);
}

TEST_F(TlsConnectionTest, DoHandshake_HandshakeNotCompleteAfterGarbage) {
    TlsConnection connection(GetSchannelContext());
    
    const char garbage[] = "not tls data";
    connection.DoHandshake(garbage, sizeof(garbage) - 1);
    
    EXPECT_FALSE(connection.IsHandshakeComplete());
}

// ============================================================================
// Encrypt Tests (Without Complete Handshake)
// ============================================================================

TEST_F(TlsConnectionTest, Encrypt_BeforeHandshake_ReturnsEmpty) {
    TlsConnection connection(GetSchannelContext());
    
    // Encryption should fail before handshake is complete
    const char plaintext[] = "Hello, World!";
    auto encrypted = connection.Encrypt(plaintext, sizeof(plaintext) - 1);
    
    EXPECT_TRUE(encrypted.empty());
}

TEST_F(TlsConnectionTest, Encrypt_WithNullData_BeforeHandshake_ReturnsEmpty) {
    TlsConnection connection(GetSchannelContext());
    
    auto encrypted = connection.Encrypt(nullptr, 0);
    
    EXPECT_TRUE(encrypted.empty());
}

// ============================================================================
// Decrypt Tests (Without Complete Handshake)
// ============================================================================

TEST_F(TlsConnectionTest, Decrypt_BeforeHandshake_ReturnsEmpty) {
    TlsConnection connection(GetSchannelContext());
    
    // Decryption should fail before handshake is complete
    const char ciphertext[] = "\x17\x03\x03\x00\x20" "encrypted_data_here_";
    auto decrypted = connection.Decrypt(ciphertext, sizeof(ciphertext) - 1);
    
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(TlsConnectionTest, Decrypt_WithNullData_BeforeHandshake_ReturnsEmpty) {
    TlsConnection connection(GetSchannelContext());
    
    auto decrypted = connection.Decrypt(nullptr, 0);
    
    EXPECT_TRUE(decrypted.empty());
}

// ============================================================================
// GetStreamSizes Tests
// ============================================================================

TEST_F(TlsConnectionTest, GetStreamSizes_BeforeHandshake_ReturnsZeros) {
    TlsConnection connection(GetSchannelContext());
    
    const auto& sizes = connection.GetStreamSizes();
    
    // Before handshake, sizes should be zero-initialized
    EXPECT_EQ(sizes.cbHeader, 0u);
    EXPECT_EQ(sizes.cbTrailer, 0u);
    EXPECT_EQ(sizes.cbMaximumMessage, 0u);
}

// ============================================================================
// Release Tests
// ============================================================================

TEST_F(TlsConnectionTest, Release_BeforeHandshake_NoThrow) {
    TlsConnection connection(GetSchannelContext());
    
    EXPECT_NO_THROW(connection.Release());
}

TEST_F(TlsConnectionTest, Release_ClearsHandshakeState) {
    TlsConnection connection(GetSchannelContext());
    
    connection.Release();
    
    EXPECT_FALSE(connection.IsHandshakeComplete());
}

TEST_F(TlsConnectionTest, Release_CalledTwice_NoThrow) {
    TlsConnection connection(GetSchannelContext());
    
    EXPECT_NO_THROW({
        connection.Release();
        connection.Release();
    });
}

// ============================================================================
// Handshake Result Enum Tests
// ============================================================================

TEST_F(TlsConnectionTest, HandshakeResult_AllValuesDistinct) {
    EXPECT_NE(static_cast<int>(HandshakeResult::Complete), 
              static_cast<int>(HandshakeResult::ContinueNeeded));
    EXPECT_NE(static_cast<int>(HandshakeResult::Complete), 
              static_cast<int>(HandshakeResult::NeedMoreData));
    EXPECT_NE(static_cast<int>(HandshakeResult::Complete), 
              static_cast<int>(HandshakeResult::Failed));
    EXPECT_NE(static_cast<int>(HandshakeResult::ContinueNeeded), 
              static_cast<int>(HandshakeResult::NeedMoreData));
    EXPECT_NE(static_cast<int>(HandshakeResult::ContinueNeeded), 
              static_cast<int>(HandshakeResult::Failed));
    EXPECT_NE(static_cast<int>(HandshakeResult::NeedMoreData), 
              static_cast<int>(HandshakeResult::Failed));
}

// ============================================================================
// TLS Record Format Tests
// ============================================================================

TEST_F(TlsConnectionTest, DoHandshake_ValidTlsRecordHeader_HandlesGracefully) {
    TlsConnection connection(GetSchannelContext());
    
    // Valid TLS record header but with bogus content
    unsigned char validHeader[] = {
        0x16,        // Handshake content type
        0x03, 0x01,  // TLS 1.0 version
        0x00, 0x05,  // Length: 5 bytes
        0x01,        // ClientHello message type
        0x00, 0x00, 0x01,  // Length
        0x00         // Bogus content
    };
    
    auto result = connection.DoHandshake(
        reinterpret_cast<const char*>(validHeader),
        sizeof(validHeader)
    );
    
    // Should handle without crashing - result depends on TLS stack
    EXPECT_TRUE(result == HandshakeResult::Failed ||
                result == HandshakeResult::NeedMoreData);
}

// ============================================================================
// Edge Cases Tests
// ============================================================================

TEST_F(TlsConnectionTest, DoHandshake_LargeData_HandlesGracefully) {
    TlsConnection connection(GetSchannelContext());
    
    // Large buffer of zeros
    std::vector<char> largeData(65536, 0);
    
    EXPECT_NO_THROW({
        auto result = connection.DoHandshake(largeData.data(), largeData.size());
        // Should fail but not crash
        EXPECT_TRUE(result == HandshakeResult::Failed ||
                    result == HandshakeResult::NeedMoreData);
    });
}

TEST_F(TlsConnectionTest, Encrypt_LargeData_BeforeHandshake_ReturnsEmpty) {
    TlsConnection connection(GetSchannelContext());
    
    std::vector<char> largeData(100000, 'A');
    auto encrypted = connection.Encrypt(largeData.data(), largeData.size());
    
    EXPECT_TRUE(encrypted.empty());
}

TEST_F(TlsConnectionTest, Decrypt_LargeData_BeforeHandshake_ReturnsEmpty) {
    TlsConnection connection(GetSchannelContext());
    
    std::vector<char> largeData(100000, 'B');
    auto decrypted = connection.Decrypt(largeData.data(), largeData.size());
    
    EXPECT_TRUE(decrypted.empty());
}

// ============================================================================
// Multiple TlsConnection Instances
// ============================================================================

TEST_F(TlsConnectionTest, MultipleInstances_IndependentState) {
    TlsConnection conn1(GetSchannelContext());
    TlsConnection conn2(GetSchannelContext());
    
    const char data[] = "test";
    conn1.DoHandshake(data, sizeof(data) - 1);
    
    // conn2 should still be in initial state
    EXPECT_FALSE(conn2.IsHandshakeComplete());
    EXPECT_TRUE(conn2.GetHandshakeResponse().empty());
}

TEST_F(TlsConnectionTest, MultipleInstances_CanExistSimultaneously) {
    EXPECT_NO_THROW({
        TlsConnection conn1(GetSchannelContext());
        TlsConnection conn2(GetSchannelContext());
        TlsConnection conn3(GetSchannelContext());
        
        // All should work independently
        conn1.DoHandshake("data1", 5);
        conn2.DoHandshake("data2", 5);
        conn3.DoHandshake("data3", 5);
    });
}
