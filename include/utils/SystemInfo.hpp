#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <string>
#include <nlohmann/json.hpp>

namespace http_server {
namespace utils {

struct OsVersion {
    DWORD major;
    DWORD minor;
    DWORD build;
    std::string displayName;
};

struct SystemInfoData {
    DWORD processorCount;
    DWORD pageSize;
    DWORD allocationGranularity;
    std::string processorArchitecture;
    DWORDLONG totalPhysicalMemory;
    DWORDLONG availablePhysicalMemory;
    OsVersion osVersion;
};

class SystemInfo {
public:
    static SystemInfoData GetSystemInfo();
    static OsVersion GetOsVersion();
    static nlohmann::json ToJson(const SystemInfoData& info);
    static std::string GetPlatformName();

private:
    static std::string ArchitectureToString(WORD arch);
};

} // namespace utils
} // namespace http_server
