#include "server/HttpServer.hpp"
#include "utils/Logger.hpp"

#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>

namespace {
    std::atomic<bool> g_running{true};
    http_server::HttpServer* g_server = nullptr;

    BOOL WINAPI ConsoleHandler(DWORD signal) {
        if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
            http_server::utils::Logger::Info("Shutdown signal received");
            g_running.store(false, std::memory_order_release);
            if (g_server) {
                g_server->Stop();
            }
            return TRUE;
        }
        return FALSE;
    }

    void PrintUsage(const char* program) {
        std::cout << "Usage: " << program << " [options]\n"
                  << "Options:\n"
                  << "  -p, --port <port>     HTTP port (default: 8080)\n"
                  << "  -s, --https-port <port>  HTTPS port (default: 8443)\n"
                  << "  --https               Enable HTTPS\n"
                  << "  --cert <subject>      Certificate subject name for HTTPS\n"
                  << "  -t, --threads <n>     Thread pool size (default: CPU * 2)\n"
                  << "  -v, --verbose         Enable verbose logging\n"
                  << "  -h, --help            Show this help\n"
                  << std::endl;
    }

    http_server::ServerConfig ParseArgs(int argc, char* argv[]) {
        http_server::ServerConfig config;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];

            if (arg == "-p" || arg == "--port") {
                if (i + 1 < argc) {
                    config.port = static_cast<uint16_t>(std::stoi(argv[++i]));
                }
            } else if (arg == "-s" || arg == "--https-port") {
                if (i + 1 < argc) {
                    config.httpsPort = static_cast<uint16_t>(std::stoi(argv[++i]));
                }
            } else if (arg == "--https") {
                config.enableHttps = true;
            } else if (arg == "--cert") {
                if (i + 1 < argc) {
                    std::string certSubject = argv[++i];
                    config.certificateSubject = std::wstring(certSubject.begin(), certSubject.end());
                }
            } else if (arg == "-t" || arg == "--threads") {
                if (i + 1 < argc) {
                    config.threadPoolSize = static_cast<size_t>(std::stoi(argv[++i]));
                }
            } else if (arg == "-v" || arg == "--verbose") {
                http_server::utils::Logger::SetLevel(http_server::utils::LogLevel::Debug);
            } else if (arg == "-h" || arg == "--help") {
                PrintUsage(argv[0]);
                std::exit(0);
            }
        }

        return config;
    }
}

int main(int argc, char* argv[]) {
    try {
        http_server::ServerConfig config = ParseArgs(argc, argv);
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);

        http_server::HttpServer server(config);
        g_server = &server;

        server.Start();

        std::cout << "\n"
                  << "========================================\n"
                  << "  Async HTTP Server v" << config.serverVersion << "\n"
                  << "========================================\n"
                  << "  HTTP:  http://localhost:" << server.GetPort() << "\n";

        if (config.enableHttps) {
            std::cout << "  HTTPS: https://localhost:" << server.GetHttpsPort() << "\n";
        }

        std::cout << "\n"
                  << "  Endpoints:\n"
                  << "    GET  /info       - Server information\n"
                  << "    POST /data       - Store data\n"
                  << "    GET  /data/:key  - Get data by key\n"
                  << "    GET  /data       - Get all data\n"
                  << "\n"
                  << "  Press Ctrl+C to stop the server\n"
                  << "========================================\n"
                  << std::endl;

        while (g_running.load(std::memory_order_acquire) && server.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

    } catch (const std::exception& e) {
        http_server::utils::Logger::Error("Fatal error: " + std::string(e.what()));
        return 1;
    }

    return 0;
}
