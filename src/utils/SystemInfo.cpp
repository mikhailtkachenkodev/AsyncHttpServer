#include "utils/SystemInfo.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

// Manually declare RtlGetVersion since winternl.h may not properly export it
typedef LONG NTSTATUS;
typedef struct _OSVERSIONINFOW_RTL {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR szCSDVersion[128];
} OSVERSIONINFOW_RTL;

extern "C" NTSTATUS __stdcall RtlGetVersion(OSVERSIONINFOW_RTL* lpVersionInformation);

#pragma comment(lib, "ntdll.lib")

namespace http_server {
namespace utils {

SystemInfoData SystemInfo::GetSystemInfo() {
    SystemInfoData data{};

    SYSTEM_INFO sysInfo;
    ::GetSystemInfo(&sysInfo);

    data.processorCount = sysInfo.dwNumberOfProcessors;
    data.pageSize = sysInfo.dwPageSize;
    data.allocationGranularity = sysInfo.dwAllocationGranularity;
    data.processorArchitecture = ArchitectureToString(sysInfo.wProcessorArchitecture);

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        data.totalPhysicalMemory = memStatus.ullTotalPhys;
        data.availablePhysicalMemory = memStatus.ullAvailPhys;
    }

    data.osVersion = GetOsVersion();

    return data;
}

OsVersion SystemInfo::GetOsVersion() {
    OsVersion version{};

    OSVERSIONINFOW_RTL osInfo{};
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);

    if (RtlGetVersion(&osInfo) == 0) {
        version.major = osInfo.dwMajorVersion;
        version.minor = osInfo.dwMinorVersion;
        version.build = osInfo.dwBuildNumber;

        if (osInfo.dwMajorVersion == 10) {
            if (osInfo.dwBuildNumber >= 22000) {
                version.displayName = "Windows 11";
            } else {
                version.displayName = "Windows 10";
            }
        } else if (osInfo.dwMajorVersion == 6) {
            switch (osInfo.dwMinorVersion) {
                case 3: version.displayName = "Windows 8.1"; break;
                case 2: version.displayName = "Windows 8"; break;
                case 1: version.displayName = "Windows 7"; break;
                case 0: version.displayName = "Windows Vista"; break;
                default: version.displayName = "Windows"; break;
            }
        } else {
            version.displayName = "Windows";
        }

        version.displayName += " (Build " + std::to_string(osInfo.dwBuildNumber) + ")";
    }

    return version;
}

nlohmann::json SystemInfo::ToJson(const SystemInfoData& info) {
    return nlohmann::json{
        {"processorCount", info.processorCount},
        {"pageSize", info.pageSize},
        {"processorArchitecture", info.processorArchitecture},
        {"totalMemoryMB", info.totalPhysicalMemory / (1024 * 1024)},
        {"availableMemoryMB", info.availablePhysicalMemory / (1024 * 1024)},
        {"osVersion", {
            {"major", info.osVersion.major},
            {"minor", info.osVersion.minor},
            {"build", info.osVersion.build},
            {"displayName", info.osVersion.displayName}
        }}
    };
}

std::string SystemInfo::GetPlatformName() {
    return "Windows";
}

std::string SystemInfo::ArchitectureToString(WORD arch) {
    switch (arch) {
        case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
        case PROCESSOR_ARCHITECTURE_ARM: return "ARM";
        case PROCESSOR_ARCHITECTURE_ARM64: return "ARM64";
        case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
        default: return "Unknown";
    }
}

} // namespace utils
} // namespace http_server
