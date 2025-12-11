#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>

#include <vector>
#include <string>

namespace http_server {
namespace security {

class SchannelContext;

enum class HandshakeResult {
    Complete,
    ContinueNeeded,
    NeedMoreData,
    Failed
};

class TlsConnection {
public:
    explicit TlsConnection(SchannelContext& context);
    ~TlsConnection();

    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;

    HandshakeResult DoHandshake(const char* clientData, size_t length);

    const std::vector<char>& GetHandshakeResponse() const { return m_handshakeResponse; }
    void ClearHandshakeResponse() { m_handshakeResponse.clear(); }

    bool IsHandshakeComplete() const { return m_handshakeComplete; }

    std::vector<char> Encrypt(const char* plaintext, size_t length);

    std::vector<char> Decrypt(const char* ciphertext, size_t length);

    const SecPkgContext_StreamSizes& GetStreamSizes() const { return m_streamSizes; }

    void Release();

private:
    HandshakeResult ProcessHandshakeToken(const char* data, size_t length);

    SchannelContext& m_schannelContext;
    CtxtHandle m_securityContext;
    SecPkgContext_StreamSizes m_streamSizes;
    bool m_handshakeComplete;
    bool m_firstCall;
    std::vector<char> m_handshakeResponse;
    std::vector<char> m_decryptBuffer;
    ULONG m_contextAttributes;
};

} // namespace security
} // namespace http_server
