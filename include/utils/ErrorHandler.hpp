#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <string>

namespace http_server {
namespace utils {

class ErrorHandler {
public:
    static std::string GetLastErrorMessage();
    static std::string GetErrorMessage(DWORD errorCode);
    static std::string GetWsaErrorMessage();
    static std::string GetWsaErrorMessage(int wsaError);
    static std::string GetSchannelErrorMessage(LONG status);
    static std::string FormatError(const std::string& context, DWORD errorCode);
    static std::string FormatWsaError(const std::string& context, int wsaError);
};

} // namespace utils
} // namespace http_server
