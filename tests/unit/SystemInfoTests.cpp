#include "utils/SystemInfo.hpp"

#include <gtest/gtest.h>

using namespace http_server::utils;

class SystemInfoTest : public ::testing::Test {
protected:
    SystemInfoData info;

    void SetUp() override {
        info = SystemInfo::GetSystemInfo();
    }
};

TEST_F(SystemInfoTest, GetSystemInfoReturnsValidProcessorCount) {
    EXPECT_GT(info.processorCount, 0u);
}

TEST_F(SystemInfoTest, GetSystemInfoReturnsValidPageSize) {
    EXPECT_GT(info.pageSize, 0u);
    EXPECT_EQ(info.pageSize % 1024, 0u);
}

TEST_F(SystemInfoTest, GetSystemInfoReturnsValidAllocationGranularity) {
    EXPECT_GT(info.allocationGranularity, 0u);
}

TEST_F(SystemInfoTest, GetSystemInfoReturnsValidArchitecture) {
    EXPECT_FALSE(info.processorArchitecture.empty());
    bool validArch = (info.processorArchitecture == "x64" ||
                      info.processorArchitecture == "x86" ||
                      info.processorArchitecture == "ARM" ||
                      info.processorArchitecture == "ARM64" ||
                      info.processorArchitecture == "Unknown");
    EXPECT_TRUE(validArch);
}

TEST_F(SystemInfoTest, GetSystemInfoReturnsValidMemory) {
    EXPECT_GT(info.totalPhysicalMemory, 0ull);
    EXPECT_GT(info.availablePhysicalMemory, 0ull);
    EXPECT_LE(info.availablePhysicalMemory, info.totalPhysicalMemory);
}

TEST_F(SystemInfoTest, GetSystemInfoReturnsValidOsVersion) {
    EXPECT_GT(info.osVersion.major, 0u);
    EXPECT_FALSE(info.osVersion.displayName.empty());
}

TEST_F(SystemInfoTest, GetOsVersionReturnsConsistentData) {
    OsVersion version = SystemInfo::GetOsVersion();
    EXPECT_EQ(version.major, info.osVersion.major);
    EXPECT_EQ(version.minor, info.osVersion.minor);
    EXPECT_EQ(version.build, info.osVersion.build);
}

TEST_F(SystemInfoTest, OsVersionDisplayNameContainsWindows) {
    EXPECT_NE(info.osVersion.displayName.find("Windows"), std::string::npos);
}

TEST_F(SystemInfoTest, OsVersionDisplayNameContainsBuildNumber) {
    EXPECT_NE(info.osVersion.displayName.find("Build"), std::string::npos);
}

TEST_F(SystemInfoTest, GetPlatformNameReturnsWindows) {
    EXPECT_EQ(SystemInfo::GetPlatformName(), "Windows");
}

TEST_F(SystemInfoTest, ToJsonContainsAllFields) {
    nlohmann::json json = SystemInfo::ToJson(info);

    EXPECT_TRUE(json.contains("processorCount"));
    EXPECT_TRUE(json.contains("pageSize"));
    EXPECT_TRUE(json.contains("processorArchitecture"));
    EXPECT_TRUE(json.contains("totalMemoryMB"));
    EXPECT_TRUE(json.contains("availableMemoryMB"));
    EXPECT_TRUE(json.contains("osVersion"));
}

TEST_F(SystemInfoTest, ToJsonProcessorCountMatchesData) {
    nlohmann::json json = SystemInfo::ToJson(info);
    EXPECT_EQ(json["processorCount"].get<DWORD>(), info.processorCount);
}

TEST_F(SystemInfoTest, ToJsonPageSizeMatchesData) {
    nlohmann::json json = SystemInfo::ToJson(info);
    EXPECT_EQ(json["pageSize"].get<DWORD>(), info.pageSize);
}

TEST_F(SystemInfoTest, ToJsonArchitectureMatchesData) {
    nlohmann::json json = SystemInfo::ToJson(info);
    EXPECT_EQ(json["processorArchitecture"].get<std::string>(), info.processorArchitecture);
}

TEST_F(SystemInfoTest, ToJsonMemoryConvertedToMB) {
    nlohmann::json json = SystemInfo::ToJson(info);

    auto expectedTotalMB = info.totalPhysicalMemory / (1024 * 1024);
    auto expectedAvailMB = info.availablePhysicalMemory / (1024 * 1024);

    EXPECT_EQ(json["totalMemoryMB"].get<DWORDLONG>(), expectedTotalMB);
    EXPECT_EQ(json["availableMemoryMB"].get<DWORDLONG>(), expectedAvailMB);
}

TEST_F(SystemInfoTest, ToJsonOsVersionContainsAllFields) {
    nlohmann::json json = SystemInfo::ToJson(info);

    EXPECT_TRUE(json["osVersion"].contains("major"));
    EXPECT_TRUE(json["osVersion"].contains("minor"));
    EXPECT_TRUE(json["osVersion"].contains("build"));
    EXPECT_TRUE(json["osVersion"].contains("displayName"));
}

TEST_F(SystemInfoTest, ToJsonOsVersionMatchesData) {
    nlohmann::json json = SystemInfo::ToJson(info);

    EXPECT_EQ(json["osVersion"]["major"].get<DWORD>(), info.osVersion.major);
    EXPECT_EQ(json["osVersion"]["minor"].get<DWORD>(), info.osVersion.minor);
    EXPECT_EQ(json["osVersion"]["build"].get<DWORD>(), info.osVersion.build);
    EXPECT_EQ(json["osVersion"]["displayName"].get<std::string>(), info.osVersion.displayName);
}

TEST_F(SystemInfoTest, ToJsonIsValidJson) {
    nlohmann::json json = SystemInfo::ToJson(info);
    std::string serialized = json.dump();

    EXPECT_NO_THROW({
        auto parsed = nlohmann::json::parse(serialized);
    });
}

TEST_F(SystemInfoTest, MultipleCallsReturnConsistentData) {
    auto info1 = SystemInfo::GetSystemInfo();
    auto info2 = SystemInfo::GetSystemInfo();

    EXPECT_EQ(info1.processorCount, info2.processorCount);
    EXPECT_EQ(info1.pageSize, info2.pageSize);
    EXPECT_EQ(info1.processorArchitecture, info2.processorArchitecture);
    EXPECT_EQ(info1.osVersion.major, info2.osVersion.major);
}
