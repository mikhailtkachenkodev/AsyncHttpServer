#include "security/SchannelContext.hpp"
#include "utils/Logger.hpp"
#include "utils/ErrorHandler.hpp"

namespace http_server {
namespace security {

SchannelContext::SchannelContext()
    : m_certificateContext(nullptr)
    , m_certStore(nullptr)
    , m_initialized(false) {
    SecInvalidateHandle(&m_credentials);
}

SchannelContext::~SchannelContext() {
    Release();
}

bool SchannelContext::Initialize(const std::wstring& certificateSubject) {
    if (m_initialized) {
        return true;
    }

    m_certificateContext = LoadCertificate(certificateSubject);
    if (!m_certificateContext) {
        utils::Logger::Error("Failed to load certificate: " +
            std::string(certificateSubject.begin(), certificateSubject.end()));
        return false;
    }

    SCHANNEL_CRED schCred = {};
    schCred.dwVersion = SCHANNEL_CRED_VERSION;
    schCred.cCreds = 1;
    schCred.paCred = &m_certificateContext;
    schCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    schCred.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_SYSTEM_MAPPER;

    TimeStamp expiry;
    SECURITY_STATUS status = AcquireCredentialsHandleW(
        nullptr,
        const_cast<LPWSTR>(UNISP_NAME_W),
        SECPKG_CRED_INBOUND,
        nullptr,
        &schCred,
        nullptr,
        nullptr,
        &m_credentials,
        &expiry
    );

    if (status != SEC_E_OK) {
        utils::Logger::Error("AcquireCredentialsHandle failed: " +
            utils::ErrorHandler::GetSchannelErrorMessage(status));
        CertFreeCertificateContext(m_certificateContext);
        m_certificateContext = nullptr;
        return false;
    }

    m_initialized = true;
    utils::Logger::Info("Schannel initialized successfully");
    return true;
}

PCCERT_CONTEXT SchannelContext::LoadCertificate(const std::wstring& subject) {
    m_certStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        L"MY"
    );

    if (m_certStore) {
        PCCERT_CONTEXT cert = CertFindCertificateInStore(
            m_certStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR_W,
            subject.c_str(),
            nullptr
        );

        if (cert) {
            utils::Logger::Debug("Certificate found in Local Machine store");
            return cert;
        }

        CertCloseStore(m_certStore, 0);
    }

    m_certStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY"
    );

    if (m_certStore) {
        PCCERT_CONTEXT cert = CertFindCertificateInStore(
            m_certStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR_W,
            subject.c_str(),
            nullptr
        );

        if (cert) {
            utils::Logger::Debug("Certificate found in Current User store");
            return cert;
        }

        CertCloseStore(m_certStore, 0);
        m_certStore = nullptr;
    }

    utils::Logger::Error("Certificate not found in any store");
    return nullptr;
}

void SchannelContext::Release() {
    if (m_initialized) {
        FreeCredentialsHandle(&m_credentials);
        SecInvalidateHandle(&m_credentials);
        m_initialized = false;
    }

    if (m_certificateContext) {
        CertFreeCertificateContext(m_certificateContext);
        m_certificateContext = nullptr;
    }

    if (m_certStore) {
        CertCloseStore(m_certStore, 0);
        m_certStore = nullptr;
    }
}

} // namespace security
} // namespace http_server
