#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

#include <string>
#include <memory>

namespace http_server {
namespace security {

class SchannelContext {
public:
    SchannelContext();
    ~SchannelContext();

    SchannelContext(const SchannelContext&) = delete;
    SchannelContext& operator=(const SchannelContext&) = delete;

    bool Initialize(const std::wstring& certificateSubject);

    CredHandle* GetCredentials() { return &m_credentials; }
    const CredHandle* GetCredentials() const { return &m_credentials; }

    bool IsInitialized() const { return m_initialized; }

    void Release();

private:
    PCCERT_CONTEXT LoadCertificate(const std::wstring& subject);

    CredHandle m_credentials;
    PCCERT_CONTEXT m_certificateContext;
    HCERTSTORE m_certStore;
    bool m_initialized;
};

} // namespace security
} // namespace http_server
