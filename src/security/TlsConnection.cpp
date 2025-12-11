#include "security/TlsConnection.hpp"
#include "security/SchannelContext.hpp"
#include "utils/Logger.hpp"
#include "utils/ErrorHandler.hpp"

namespace http_server {
namespace security {

TlsConnection::TlsConnection(SchannelContext& context)
    : m_schannelContext(context)
    , m_handshakeComplete(false)
    , m_firstCall(true)
    , m_contextAttributes(0) {
    SecInvalidateHandle(&m_securityContext);
    ZeroMemory(&m_streamSizes, sizeof(m_streamSizes));
}

TlsConnection::~TlsConnection() {
    Release();
}

HandshakeResult TlsConnection::DoHandshake(const char* clientData, size_t length) {
    return ProcessHandshakeToken(clientData, length);
}

HandshakeResult TlsConnection::ProcessHandshakeToken(const char* data, size_t length) {
    SecBuffer inBuffers[2];
    inBuffers[0].pvBuffer = const_cast<char*>(data);
    inBuffers[0].cbBuffer = static_cast<ULONG>(length);
    inBuffers[0].BufferType = SECBUFFER_TOKEN;

    inBuffers[1].pvBuffer = nullptr;
    inBuffers[1].cbBuffer = 0;
    inBuffers[1].BufferType = SECBUFFER_EMPTY;

    SecBufferDesc inBufferDesc;
    inBufferDesc.ulVersion = SECBUFFER_VERSION;
    inBufferDesc.cBuffers = 2;
    inBufferDesc.pBuffers = inBuffers;

    SecBuffer outBuffers[1];
    outBuffers[0].pvBuffer = nullptr;
    outBuffers[0].cbBuffer = 0;
    outBuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outBufferDesc;
    outBufferDesc.ulVersion = SECBUFFER_VERSION;
    outBufferDesc.cBuffers = 1;
    outBufferDesc.pBuffers = outBuffers;

    ULONG contextReq = ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM |
                       ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_EXTENDED_ERROR;

    TimeStamp expiry;

    SECURITY_STATUS status = AcceptSecurityContext(
        m_schannelContext.GetCredentials(),
        m_firstCall ? nullptr : &m_securityContext,
        &inBufferDesc,
        contextReq,
        0,
        &m_securityContext,
        &outBufferDesc,
        &m_contextAttributes,
        &expiry
    );

    m_firstCall = false;

    m_handshakeResponse.clear();
    if (outBuffers[0].cbBuffer > 0 && outBuffers[0].pvBuffer) {
        m_handshakeResponse.assign(
            static_cast<char*>(outBuffers[0].pvBuffer),
            static_cast<char*>(outBuffers[0].pvBuffer) + outBuffers[0].cbBuffer
        );
        FreeContextBuffer(outBuffers[0].pvBuffer);
    }

    switch (status) {
        case SEC_E_OK:
            m_handshakeComplete = true;

            status = QueryContextAttributesW(&m_securityContext, SECPKG_ATTR_STREAM_SIZES, &m_streamSizes);
            if (status != SEC_E_OK) {
                utils::Logger::Error("QueryContextAttributes failed: " +
                    utils::ErrorHandler::GetSchannelErrorMessage(status));
                return HandshakeResult::Failed;
            }

            utils::Logger::Debug("TLS handshake complete, response size: " + 
                std::to_string(m_handshakeResponse.size()));
            
            if (!m_handshakeResponse.empty()) {
                return HandshakeResult::ContinueNeeded;
            }
            return HandshakeResult::Complete;

        case SEC_I_CONTINUE_NEEDED:
            utils::Logger::Debug("TLS handshake continue needed, response size: " + 
                std::to_string(m_handshakeResponse.size()));
            return HandshakeResult::ContinueNeeded;

        case SEC_E_INCOMPLETE_MESSAGE:
            m_handshakeResponse.clear();
            return HandshakeResult::NeedMoreData;

        default:
            utils::Logger::Error("AcceptSecurityContext failed: " +
                utils::ErrorHandler::GetSchannelErrorMessage(status));
            return HandshakeResult::Failed;
    }
}

std::vector<char> TlsConnection::Encrypt(const char* plaintext, size_t length) {
    if (!m_handshakeComplete) {
        return {};
    }

    // Validate message size to prevent integer overflow
    constexpr size_t MAX_MESSAGE_SIZE = 16 * 1024 * 1024;  // 16MB max
    if (length > MAX_MESSAGE_SIZE) {
        utils::Logger::Error("Encrypt: message too large (" + std::to_string(length) + " bytes)");
        return {};
    }

    // Check for integer overflow in total size calculation
    size_t headerTrailerSize = static_cast<size_t>(m_streamSizes.cbHeader) + m_streamSizes.cbTrailer;
    if (length > SIZE_MAX - headerTrailerSize) {
        utils::Logger::Error("Encrypt: integer overflow in size calculation");
        return {};
    }

    size_t totalSize = headerTrailerSize + length;
    std::vector<char> buffer(totalSize);

    std::memcpy(buffer.data() + m_streamSizes.cbHeader, plaintext, length);

    SecBuffer buffers[4];
    buffers[0].pvBuffer = buffer.data();
    buffers[0].cbBuffer = m_streamSizes.cbHeader;
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    buffers[1].pvBuffer = buffer.data() + m_streamSizes.cbHeader;
    buffers[1].cbBuffer = static_cast<ULONG>(length);
    buffers[1].BufferType = SECBUFFER_DATA;

    buffers[2].pvBuffer = buffer.data() + m_streamSizes.cbHeader + length;
    buffers[2].cbBuffer = m_streamSizes.cbTrailer;
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    buffers[3].pvBuffer = nullptr;
    buffers[3].cbBuffer = 0;
    buffers[3].BufferType = SECBUFFER_EMPTY;

    SecBufferDesc bufferDesc;
    bufferDesc.ulVersion = SECBUFFER_VERSION;
    bufferDesc.cBuffers = 4;
    bufferDesc.pBuffers = buffers;

    SECURITY_STATUS status = EncryptMessage(&m_securityContext, 0, &bufferDesc, 0);
    if (status != SEC_E_OK) {
        utils::Logger::Error("EncryptMessage failed: " +
            utils::ErrorHandler::GetSchannelErrorMessage(status));
        return {};
    }

    size_t encryptedSize = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
    buffer.resize(encryptedSize);

    return buffer;
}

std::vector<char> TlsConnection::Decrypt(const char* ciphertext, size_t length) {
    if (!m_handshakeComplete) {
        return {};
    }

    m_decryptBuffer.insert(m_decryptBuffer.end(), ciphertext, ciphertext + length);

    std::vector<char> decrypted;

    while (!m_decryptBuffer.empty()) {
        SecBuffer buffers[4];
        buffers[0].pvBuffer = m_decryptBuffer.data();
        buffers[0].cbBuffer = static_cast<ULONG>(m_decryptBuffer.size());
        buffers[0].BufferType = SECBUFFER_DATA;

        buffers[1].pvBuffer = nullptr;
        buffers[1].cbBuffer = 0;
        buffers[1].BufferType = SECBUFFER_EMPTY;

        buffers[2].pvBuffer = nullptr;
        buffers[2].cbBuffer = 0;
        buffers[2].BufferType = SECBUFFER_EMPTY;

        buffers[3].pvBuffer = nullptr;
        buffers[3].cbBuffer = 0;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc bufferDesc;
        bufferDesc.ulVersion = SECBUFFER_VERSION;
        bufferDesc.cBuffers = 4;
        bufferDesc.pBuffers = buffers;

        SECURITY_STATUS status = DecryptMessage(&m_securityContext, &bufferDesc, 0, nullptr);

        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            break;
        }

        if (status != SEC_E_OK && status != SEC_I_RENEGOTIATE && status != SEC_I_CONTEXT_EXPIRED) {
            utils::Logger::Error("DecryptMessage failed: " +
                utils::ErrorHandler::GetSchannelErrorMessage(status));
            m_decryptBuffer.clear();
            return decrypted;
        }

        SecBuffer* dataBuffer = nullptr;
        SecBuffer* extraBuffer = nullptr;

        for (int i = 0; i < 4; ++i) {
            if (buffers[i].BufferType == SECBUFFER_DATA) {
                dataBuffer = &buffers[i];
            } else if (buffers[i].BufferType == SECBUFFER_EXTRA) {
                extraBuffer = &buffers[i];
            }
        }

        if (dataBuffer && dataBuffer->cbBuffer > 0) {
            const char* dataPtr = static_cast<const char*>(dataBuffer->pvBuffer);
            decrypted.insert(decrypted.end(), dataPtr, dataPtr + dataBuffer->cbBuffer);
        }

        if (extraBuffer && extraBuffer->cbBuffer > 0) {
            std::vector<char> extra(
                static_cast<const char*>(extraBuffer->pvBuffer),
                static_cast<const char*>(extraBuffer->pvBuffer) + extraBuffer->cbBuffer
            );
            m_decryptBuffer = std::move(extra);
        } else {
            m_decryptBuffer.clear();
        }

        if (status == SEC_I_CONTEXT_EXPIRED) {
            break;
        }

        if (status == SEC_I_RENEGOTIATE) {
            utils::Logger::Warning("TLS renegotiation requested");
            break;
        }
    }

    return decrypted;
}

void TlsConnection::Release() {
    if (SecIsValidHandle(&m_securityContext)) {
        DeleteSecurityContext(&m_securityContext);
        SecInvalidateHandle(&m_securityContext);
    }
    m_handshakeComplete = false;
    m_firstCall = true;
    m_handshakeResponse.clear();
    m_decryptBuffer.clear();
}

} // namespace security
} // namespace http_server
