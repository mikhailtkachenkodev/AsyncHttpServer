#include "security/SchannelContext.hpp"
#include "utils/Logger.hpp"

#include <gtest/gtest.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

using namespace http_server::security;

class SchannelContextTest : public ::testing::Test {
protected:
    void SetUp() override {
        http_server::utils::Logger::SetLevel(http_server::utils::LogLevel::Warning);
    }
};

// ============================================================================
// Construction and Destruction Tests
// ============================================================================

TEST_F(SchannelContextTest, DefaultConstructor_NotInitialized) {
    SchannelContext context;
    EXPECT_FALSE(context.IsInitialized());
}

TEST_F(SchannelContextTest, Destructor_NoThrow) {
    EXPECT_NO_THROW({
        SchannelContext context;
        // Let it destruct
    });
}

TEST_F(SchannelContextTest, DestructorAfterInitialize_NoThrow) {
    EXPECT_NO_THROW({
        SchannelContext context;
        context.Initialize(L"localhost");  // May or may not succeed
        // Let it destruct
    });
}

// ============================================================================
// Initialize Tests
// ============================================================================

TEST_F(SchannelContextTest, Initialize_WithValidCertificate_ReturnsTrue) {
    SchannelContext context;
    
    // This test requires a "localhost" certificate in the certificate store
    bool result = context.Initialize(L"localhost");
    
    if (result) {
        EXPECT_TRUE(context.IsInitialized());
        EXPECT_NE(context.GetCredentials(), nullptr);
    } else {
        // Certificate not found - skip this assertion
        GTEST_SKIP() << "localhost certificate not installed";
    }
}

TEST_F(SchannelContextTest, Initialize_WithNonexistentCertificate_ReturnsFalse) {
    SchannelContext context;
    
    // Use a certificate subject that definitely doesn't exist
    bool result = context.Initialize(L"nonexistent_certificate_subject_12345");
    
    EXPECT_FALSE(result);
    EXPECT_FALSE(context.IsInitialized());
}

TEST_F(SchannelContextTest, Initialize_EmptySubject_HandledGracefully) {
    SchannelContext context;
    
    // Empty subject behavior depends on certificates in store
    // CertFindCertificateInStore with empty string may match certificates
    // So we just verify it doesn't crash
    EXPECT_NO_THROW({
        bool result = context.Initialize(L"");
        // Result depends on certificate store contents
        (void)result;
    });
}

TEST_F(SchannelContextTest, Initialize_CalledTwice_ReturnsTrue) {
    SchannelContext context;
    
    bool firstResult = context.Initialize(L"localhost");
    if (!firstResult) {
        GTEST_SKIP() << "localhost certificate not installed";
    }
    
    // Second call should return true (already initialized)
    bool secondResult = context.Initialize(L"localhost");
    
    EXPECT_TRUE(secondResult);
    EXPECT_TRUE(context.IsInitialized());
}

TEST_F(SchannelContextTest, Initialize_SpecialCharactersInSubject_ReturnsFalse) {
    SchannelContext context;
    
    // Subject with special characters that definitely won't match
    bool result = context.Initialize(L"!@#$%^&*()");
    
    EXPECT_FALSE(result);
    EXPECT_FALSE(context.IsInitialized());
}

// ============================================================================
// GetCredentials Tests
// ============================================================================

TEST_F(SchannelContextTest, GetCredentials_BeforeInitialize_ReturnsPointer) {
    SchannelContext context;
    
    // GetCredentials should return a valid pointer even before initialize
    // (it's the address of the internal handle)
    EXPECT_NE(context.GetCredentials(), nullptr);
}

TEST_F(SchannelContextTest, GetCredentials_ConstVersion_ReturnsPointer) {
    const SchannelContext context;
    
    EXPECT_NE(context.GetCredentials(), nullptr);
}

TEST_F(SchannelContextTest, GetCredentials_AfterInitialize_ReturnsValidHandle) {
    SchannelContext context;
    
    bool result = context.Initialize(L"localhost");
    if (!result) {
        GTEST_SKIP() << "localhost certificate not installed";
    }
    
    CredHandle* creds = context.GetCredentials();
    EXPECT_NE(creds, nullptr);
    
    // After successful init, handle should be valid
    EXPECT_TRUE(SecIsValidHandle(creds));
}

// ============================================================================
// Release Tests
// ============================================================================

TEST_F(SchannelContextTest, Release_BeforeInitialize_NoThrow) {
    SchannelContext context;
    
    EXPECT_NO_THROW(context.Release());
    EXPECT_FALSE(context.IsInitialized());
}

TEST_F(SchannelContextTest, Release_AfterInitialize_ClearsState) {
    SchannelContext context;
    
    bool result = context.Initialize(L"localhost");
    if (!result) {
        GTEST_SKIP() << "localhost certificate not installed";
    }
    
    EXPECT_TRUE(context.IsInitialized());
    
    context.Release();
    
    EXPECT_FALSE(context.IsInitialized());
}

TEST_F(SchannelContextTest, Release_CalledTwice_NoThrow) {
    SchannelContext context;
    
    context.Initialize(L"localhost");
    
    EXPECT_NO_THROW({
        context.Release();
        context.Release();
    });
}

TEST_F(SchannelContextTest, Release_ThenReinitialize_Works) {
    SchannelContext context;
    
    bool firstInit = context.Initialize(L"localhost");
    if (!firstInit) {
        GTEST_SKIP() << "localhost certificate not installed";
    }
    
    context.Release();
    EXPECT_FALSE(context.IsInitialized());
    
    // Should be able to initialize again
    bool secondInit = context.Initialize(L"localhost");
    EXPECT_TRUE(secondInit);
    EXPECT_TRUE(context.IsInitialized());
}

// ============================================================================
// Thread Safety (Basic) Tests
// ============================================================================

TEST_F(SchannelContextTest, NonCopyable_CompileCheck) {
    // This is a compile-time check - if it compiles, the class is properly non-copyable
    EXPECT_FALSE(std::is_copy_constructible_v<SchannelContext>);
    EXPECT_FALSE(std::is_copy_assignable_v<SchannelContext>);
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(SchannelContextTest, Initialize_UnicodeSubject_Handled) {
    SchannelContext context;
    
    // Unicode characters in subject - should handle gracefully
    bool result = context.Initialize(L"テスト証明書");
    
    // Should return false (no such certificate) without crashing
    EXPECT_FALSE(result);
}

TEST_F(SchannelContextTest, Initialize_LongSubject_Handled) {
    SchannelContext context;
    
    // Very long subject string
    std::wstring longSubject(1000, L'x');
    bool result = context.Initialize(longSubject);
    
    // Should return false without crashing
    EXPECT_FALSE(result);
}
