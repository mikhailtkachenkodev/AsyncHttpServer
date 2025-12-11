cmake_minimum_required(VERSION 3.10)
project(AsyncHttpServer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:preprocessor /utf-8)
else()
    add_compile_options(-Wall -Wextra)
endif()

# Windows-specific definitions
add_compile_definitions(_WIN32_WINNT=0x0A00) 
add_compile_definitions(UNICODE _UNICODE)
add_compile_definitions(NOMINMAX)

# Options
option(BUILD_TESTS "Build unit tests" ON)
option(ENABLE_HTTPS "Enable HTTPS support via Schannel" ON)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party)

# Windows libraries
set(WIN_LIBS ws2_32 mswsock secur32 crypt32 ntdll)

set(CORE_SOURCES
    src/core/WinsockInit.cpp
    src/core/IoCompletionPort.cpp
    src/core/ThreadPool.cpp
    src/core/ConnectionContext.cpp
    src/core/OverlappedContext.cpp
)

set(HTTP_SOURCES
    src/http/HttpParser.cpp
    src/http/HttpRequest.cpp
    src/http/HttpResponse.cpp
    src/http/HttpRouter.cpp
)

set(HANDLER_SOURCES
    src/handlers/InfoHandler.cpp
    src/handlers/DataHandler.cpp
)

set(STORAGE_SOURCES
    src/storage/ThreadSafeStore.cpp
)

set(SECURITY_SOURCES
    src/security/SchannelContext.cpp
    src/security/TlsConnection.cpp
)

set(UTILS_SOURCES
    src/utils/ErrorHandler.cpp
    src/utils/Logger.cpp
    src/utils/SystemInfo.cpp
)

set(SERVER_SOURCES
    src/server/HttpServer.cpp
)

set(LIB_SOURCES
    ${CORE_SOURCES}
    ${HTTP_SOURCES}
    ${HANDLER_SOURCES}
    ${STORAGE_SOURCES}
    ${SECURITY_SOURCES}
    ${UTILS_SOURCES}
    ${SERVER_SOURCES}
)

add_library(AsyncHttpServerLib STATIC ${LIB_SOURCES})
target_link_libraries(AsyncHttpServerLib PUBLIC ${WIN_LIBS})

add_executable(AsyncHttpServer src/main.cpp)
target_link_libraries(AsyncHttpServer PRIVATE AsyncHttpServerLib)

if(BUILD_TESTS)
    
    enable_testing()
    
    # Fetch Google Test
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.0
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    
    add_subdirectory(tests)
endif()

install(TARGETS AsyncHttpServer RUNTIME DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)