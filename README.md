# AsyncHttpServer

Высокопроизводительный асинхронный HTTP/HTTPS сервер для Windows, реализованный на C++17 с использованием I/O Completion Ports (IOCP).

## Оглавление

- [Описание проекта](#описание-проекта)
- [Реализованные требования](#реализованные-требования)
- [Архитектура](#архитектура)
- [Windows-specific решения](#windows-specific-решения)
- [Сборка проекта](#сборка-проекта)
- [Запуск сервера](#запуск-сервера)
- [API Endpoints](#api-endpoints)
- [Тестирование](#тестирование)
- [Структура проекта](#структура-проекта)

---

## Описание проекта

AsyncHttpServer — это полнофункциональный асинхронный HTTP/HTTPS сервер, разработанный специально для платформы Windows с использованием нативных API. Сервер способен обрабатывать множественные одновременные подключения с высокой производительностью благодаря использованию I/O Completion Ports — наиболее эффективного механизма асинхронного ввода-вывода в Windows.

### Ключевые особенности

- **Асинхронная обработка** на базе IOCP (I/O Completion Ports)
- **Многопоточный пул воркеров** с автоматическим масштабированием (CPU × 2)
- **Поддержка HTTPS** через Windows Schannel (нативный SSL/TLS)
- **Thread-safe хранилище** данных с оптимизированными блокировками
- **Graceful shutdown** с корректной обработкой активных соединений
- **Полная валидация** входных данных и защита от переполнения буфера
- **280 юнит-тестов** для обеспечения надёжности

---

## Реализованные требования

### Базовые требования

| Требование | Статус | Описание реализации |
|------------|--------|---------------------|
| Прослушивание TCP порта | ✅ | Асинхронный accept через AcceptEx |
| GET /info | ✅ | Возвращает JSON с версией, временем работы, системной информацией |
| POST /data | ✅ | Сохранение в thread-safe хранилище, возврат 201 Created |
| GET /data/:key | ✅ | Получение значения по ключу или 404 Not Found |
| Обработка Content-Length | ✅ | Полная поддержка в HttpParser |
| Обработка Connection | ✅ | Поддержка keep-alive и close |
| Пул потоков (CPU × 2) | ✅ | ThreadPool с автоматическим определением оптимального размера |
| WSARecv/WSASend | ✅ | Все операции через асинхронные Winsock функции |
| Обработка ошибок GetLastError | ✅ | ErrorHandler с преобразованием кодов в сообщения |
| Защита от переполнения буфера | ✅ | Лимиты на размер запроса, заголовков, тела |
| Валидация входных данных | ✅ | Проверка размера JSON, формата ключей |

### Дополнительные требования (все реализованы)

| Требование | Статус | Описание реализации |
|------------|--------|---------------------|
| HTTPS через Schannel | ✅ | Полная поддержка TLS с использованием Windows Schannel |
| Системная информация через WinAPI | ✅ | GetSystemInfo, RtlGetVersion, GlobalMemoryStatusEx |
| Юнит-тесты | ✅ | 280 тестов на Google Test |
| Graceful shutdown | ✅ | Ожидание завершения активных соединений с таймаутом |

---

## Архитектура

### Общая схема

```
┌─────────────────────────────────────────────────────────────────┐
│                         HttpServer                               │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ ListenSocket│  │ IOCP         │  │ ThreadPool             │  │
│  │ (AcceptEx)  │──│ (Completion  │──│ (Worker Threads)       │  │
│  └─────────────┘  │  Port)       │  │  ├─ HandleAccept       │  │
│                   └──────────────┘  │  ├─ HandleReceive      │  │
│                                     │  ├─ HandleSend         │  │
│  ┌─────────────────────────────┐   │  └─ HandleDisconnect   │  │
│  │ Connections Map             │   └────────────────────────┘  │
│  │ (SOCKET → ConnectionContext)│                                │
│  └─────────────────────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      HTTP Processing                             │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────────────┐ │
│  │ HttpParser │──│ HttpRouter │──│ Handlers                   │ │
│  │ (Streaming)│  │ (Pattern   │  │  ├─ InfoHandler (/info)    │ │
│  └────────────┘  │  Matching) │  │  └─ DataHandler (/data)    │ │
│                  └────────────┘  └────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Security Layer (HTTPS)                        │
│  ┌──────────────────┐  ┌─────────────────────────────────────┐  │
│  │ SchannelContext  │  │ TlsConnection                       │  │
│  │ (Credentials)    │  │ (Per-connection TLS state machine)  │  │
│  └──────────────────┘  └─────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Поток обработки запроса

1. **Accept**: `AcceptEx` постит операцию принятия соединения в IOCP
2. **Completion**: Worker thread получает завершение через `GetQueuedCompletionStatus`
3. **Receive**: `WSARecv` читает данные асинхронно в буфер `OverlappedContext`
4. **Parse**: `HttpParser` разбирает HTTP запрос (поддержка инкрементального парсинга)
5. **Route**: `HttpRouter` находит обработчик по паттерну пути
6. **Handle**: Вызывается соответствующий handler (InfoHandler/DataHandler)
7. **Send**: `WSASend` отправляет ответ асинхронно через IOCP
8. **Cleanup/Keep-alive**: Закрытие соединения или ожидание следующего запроса

### Слои архитектуры

#### Core Layer (`src/core/`)

| Компонент | Описание |
|-----------|----------|
| **WinsockInit** | RAII-инициализация Winsock 2.2, загрузка AcceptEx/GetAcceptExSockaddrs |
| **IoCompletionPort** | Обёртка над IOCP: создание, ассоциация сокетов, получение завершений |
| **ThreadPool** | Пул рабочих потоков, опрашивающих IOCP |
| **ConnectionContext** | Состояние соединения: сокет, буферы, TLS-контекст, thread-safe поля |
| **OverlappedContext** | Расширенная структура OVERLAPPED для асинхронных операций |

#### HTTP Layer (`src/http/`)

| Компонент | Описание |
|-----------|----------|
| **HttpParser** | Потоковый парсер HTTP/1.1 с защитой от переполнения |
| **HttpRequest** | Модель запроса: метод, путь, заголовки, тело, параметры |
| **HttpResponse** | Модель ответа с фабричными методами (Ok, NotFound, BadRequest и т.д.) |
| **HttpRouter** | Маршрутизация с поддержкой параметров пути (`:param` синтаксис) |

#### Security Layer (`src/security/`)

| Компонент | Описание |
|-----------|----------|
| **SchannelContext** | Управление Schannel credentials, загрузка сертификата из хранилища |
| **TlsConnection** | State machine для TLS handshake, шифрование/дешифрование данных |

#### Storage Layer (`src/storage/`)

| Компонент | Описание |
|-----------|----------|
| **ThreadSafeStore** | Key-value хранилище с `std::shared_mutex` (множественные читатели/один писатель) |

---

## Windows-specific решения

### 1. I/O Completion Ports (IOCP)

IOCP — наиболее масштабируемый механизм асинхронного I/O в Windows. В отличие от `select`/`poll`, IOCP позволяет обрабатывать тысячи соединений минимальным количеством потоков.

```cpp
// Создание Completion Port
m_completionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);

// Ассоциация сокета с IOCP
CreateIoCompletionPort((HANDLE)socket, m_completionPort, completionKey, 0);

// Получение завершений в worker thread
GetQueuedCompletionStatus(m_completionPort, &bytesTransferred,
                          &completionKey, &overlapped, INFINITE);
```

### 2. Асинхронные сокетные операции

Все операции используют перекрытый (overlapped) I/O:

```cpp
// Асинхронный Accept
AcceptEx(listenSocket, acceptSocket, buffer, 0,
         sizeof(sockaddr_in) + 16, sizeof(sockaddr_in) + 16,
         &bytesReceived, overlappedContext);

// Асинхронный Receive
WSARecv(socket, &wsaBuf, 1, &bytesReceived, &flags, overlappedContext, nullptr);

// Асинхронный Send
WSASend(socket, &wsaBuf, 1, &bytesSent, 0, overlappedContext, nullptr);
```

### 3. Schannel для HTTPS

Windows-нативная реализация TLS без внешних зависимостей:

```cpp
// Инициализация credentials
AcquireCredentialsHandle(nullptr, UNISP_NAME, SECPKG_CRED_INBOUND,
                         nullptr, &schCred, nullptr, nullptr,
                         &m_credentials, &expiry);

// TLS Handshake
AcceptSecurityContext(&credentials, contextPtr, &inBufferDesc,
                      contextReq, 0, &context, &outBufferDesc,
                      &contextAttributes, &expiry);

// Шифрование данных
EncryptMessage(&context, 0, &bufferDesc, 0);
```

### 4. Системная информация через WinAPI

```cpp
// Информация о процессоре
SYSTEM_INFO sysInfo;
GetSystemInfo(&sysInfo);
info.processorCount = sysInfo.dwNumberOfProcessors;
info.processorArchitecture = GetArchitectureString(sysInfo.wProcessorArchitecture);

// Версия ОС (через RtlGetVersion для обхода ограничений GetVersionEx)
OSVERSIONINFOEXW osInfo = {sizeof(osInfo)};
RtlGetVersion(&osInfo);

// Информация о памяти
MEMORYSTATUSEX memStatus = {sizeof(memStatus)};
GlobalMemoryStatusEx(&memStatus);
info.totalPhysicalMemory = memStatus.ullTotalPhys;
```

### 5. Обработка ошибок Windows

```cpp
// Получение описания ошибки Windows
std::string GetErrorMessage(DWORD errorCode) {
    if (errorCode == 0) return "No error";

    LPSTR buffer = nullptr;
    DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buffer, 0, nullptr);

    std::string message(buffer, size);
    LocalFree(buffer);
    return message;
}
```

### 6. Thread-safe структуры данных

```cpp
// ThreadSafeStore использует shared_mutex для оптимальной производительности
class ThreadSafeStore {
    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::string, nlohmann::json> m_data;

public:
    // Множественные читатели
    std::optional<nlohmann::json> Get(const std::string& key) const {
        std::shared_lock lock(m_mutex);
        auto it = m_data.find(key);
        return (it != m_data.end()) ? std::optional(it->second) : std::nullopt;
    }

    // Эксклюзивная запись
    bool Set(const std::string& key, const nlohmann::json& value) {
        std::unique_lock lock(m_mutex);
        m_data[key] = value;
        return true;
    }
};
```

### 7. Атомарные операции для состояния соединения

```cpp
class ConnectionContext {
    std::atomic<SOCKET> m_socket;
    std::atomic<ConnectionState> m_state;
    std::atomic<size_t> m_bytesSent;
    std::atomic<bool> m_keepAlive;

    // Безопасное закрытие сокета
    void Close() {
        std::lock_guard<std::mutex> lock(m_closeMutex);
        SOCKET sock = m_socket.exchange(INVALID_SOCKET);
        if (sock != INVALID_SOCKET) {
            shutdown(sock, SD_BOTH);
            closesocket(sock);
        }
    }
};
```

---

## Сборка проекта

### Требования

- **ОС**: Windows 10/11 или Windows Server 2019+
- **Компилятор**: MSVC 2019+ (Visual Studio 2019/2022)
- **CMake**: 3.16+
- **Сертификат** (для HTTPS): Самоподписанный или из хранилища Windows

### Сборка через CMake

```bash
# Клонирование репозитория
git clone https://github.com/your-repo/AsyncHttpServer.git
cd AsyncHttpServer

# Конфигурация (Visual Studio 2022)
cmake -B build -G "Visual Studio 17 2022"

# Сборка Release
cmake --build build --config Release

# Сборка Debug
cmake --build build --config Debug
```

### Сборка через Visual Studio

1. Откройте Visual Studio
2. Выберите "Open a local folder" и укажите папку проекта
3. Visual Studio автоматически обнаружит CMakeLists.txt
4. Выберите конфигурацию Release/Debug
5. Build → Build All

### Создание самоподписанного сертификата для HTTPS

```powershell
# Создание сертификата (PowerShell от имени Администратора)
New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 `
    -KeyAlgorithm RSA -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(1)
```

---

## Запуск сервера

### Базовый запуск (только HTTP)

```bash
build\Release\AsyncHttpServer.exe
```

Сервер запустится на порту 8080 по умолчанию.

### Запуск с параметрами

```bash
# Указание порта
build\Release\AsyncHttpServer.exe -p 9000

# HTTP + HTTPS
build\Release\AsyncHttpServer.exe -p 8080 --https --https-port 8443 --cert "localhost"

# Полный набор параметров
build\Release\AsyncHttpServer.exe \
    -p 8080 \
    --https \
    --https-port 8443 \
    --cert "localhost" \
    --threads 8 \
    --max-connections 10000
```

### Параметры командной строки

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `-p, --port` | HTTP порт | 8080 |
| `--https` | Включить HTTPS | выключено |
| `--https-port` | HTTPS порт | 8443 |
| `--cert` | Subject Name сертификата | - |
| `--threads` | Количество рабочих потоков | CPU × 2 |
| `--max-connections` | Максимум соединений | 10000 |

---

## API Endpoints

### GET /info

Возвращает информацию о сервере и системе.

**Запрос:**
```http
GET /info HTTP/1.1
Host: localhost:8080
```

**Ответ:**
```json
{
    "version": "1.0",
    "uptime": "00:15:32",
    "connections": 5,
    "platform": "Windows",
    "system": {
        "processorCount": 8,
        "pageSize": 4096,
        "processorArchitecture": "x64",
        "totalMemoryMB": 16384,
        "availableMemoryMB": 8192,
        "osVersion": {
            "major": 10,
            "minor": 0,
            "build": 22631,
            "displayName": "Windows 10 (Build 22631)"
        }
    }
}
```

### POST /data

Сохраняет данные в thread-safe хранилище.

**Запрос:**
```http
POST /data HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Content-Length: 26

{"username": "john_doe"}
```

**Ответ (успех):**
```http
HTTP/1.1 201 Created
Content-Type: application/json

{"status": "created", "key": "username"}
```

**Ответ (ошибка валидации):**
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"error": "Invalid key format"}
```

### GET /data/:key

Получает значение по ключу.

**Запрос:**
```http
GET /data/username HTTP/1.1
Host: localhost:8080
```

**Ответ (найдено):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"username": "john_doe"}
```

**Ответ (не найдено):**
```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{"error": "Key not found: username"}
```

### GET /data

Получает все сохранённые данные.

**Запрос:**
```http
GET /data HTTP/1.1
Host: localhost:8080
```

**Ответ:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "username": "john_doe",
    "email": "john@example.com"
}
```

---

## Тестирование

### Запуск юнит-тестов

```bash
# Все тесты
ctest --test-dir build -C Release --output-on-failure

# Конкретный набор тестов
build\tests\Release\HttpParserTests.exe
build\tests\Release\HttpRouterTests.exe
build\tests\Release\ThreadSafeStoreTests.exe
build\tests\Release\IntegrationTests.exe
```

### Тестирование с помощью curl

```bash
# GET /info
curl -X GET http://localhost:8080/info

# POST /data
curl -X POST http://localhost:8080/data \
    -H "Content-Type: application/json" \
    -d '{"name": "test_value"}'

# GET /data/:key
curl -X GET http://localhost:8080/data/name

# GET /data (все данные)
curl -X GET http://localhost:8080/data

# HTTPS запрос (с игнорированием самоподписанного сертификата)
curl -k -X GET https://localhost:8443/info
```

### Тестирование с помощью PowerShell

```powershell
# GET /info
Invoke-RestMethod -Uri "http://localhost:8080/info" -Method Get

# POST /data
$body = @{ name = "test_value" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8080/data" -Method Post -Body $body -ContentType "application/json"

# GET /data/:key
Invoke-RestMethod -Uri "http://localhost:8080/data/name" -Method Get

# HTTPS (игнорирование ошибки сертификата)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
Invoke-RestMethod -Uri "https://localhost:8443/info" -Method Get
```

### Тестирование с помощью Postman

1. Создайте новую коллекцию "AsyncHttpServer"
2. Добавьте запросы:
   - `GET http://localhost:8080/info`
   - `POST http://localhost:8080/data` с JSON телом
   - `GET http://localhost:8080/data/{{key}}`
3. Для HTTPS отключите проверку SSL в Settings → General → SSL certificate verification

### Нагрузочное тестирование

```bash
# Используя Apache Benchmark (ab)
ab -n 10000 -c 100 http://localhost:8080/info

# Используя wrk (если установлен)
wrk -t4 -c100 -d30s http://localhost:8080/info
```

---

## Структура проекта

```
AsyncHttpServer/
├── CMakeLists.txt              # Главный CMake файл
├── README.md                   # Документация (этот файл)
├── TASK.md                     # Техническое задание
├── CLAUDE.md                   # Инструкции для Claude Code
│
├── include/                    # Заголовочные файлы
│   ├── core/
│   │   ├── WinsockInit.hpp     # RAII инициализация Winsock
│   │   ├── IoCompletionPort.hpp # Обёртка над IOCP
│   │   ├── ThreadPool.hpp      # Пул рабочих потоков
│   │   ├── ConnectionContext.hpp # Контекст соединения
│   │   └── OverlappedContext.hpp # Расширенный OVERLAPPED
│   ├── http/
│   │   ├── HttpParser.hpp      # Потоковый HTTP парсер
│   │   ├── HttpRequest.hpp     # Модель запроса
│   │   ├── HttpResponse.hpp    # Модель ответа
│   │   ├── HttpRouter.hpp      # Маршрутизатор
│   │   └── HttpStatus.hpp      # HTTP статусы и методы
│   ├── security/
│   │   ├── SchannelContext.hpp # Schannel credentials
│   │   └── TlsConnection.hpp   # TLS state machine
│   ├── storage/
│   │   └── ThreadSafeStore.hpp # Thread-safe хранилище
│   ├── handlers/
│   │   ├── IRequestHandler.hpp # Интерфейс обработчика
│   │   ├── InfoHandler.hpp     # /info endpoint
│   │   └── DataHandler.hpp     # /data endpoints
│   ├── server/
│   │   └── HttpServer.hpp      # Главный класс сервера
│   └── utils/
│       ├── ErrorHandler.hpp    # Обработка ошибок Windows
│       ├── Logger.hpp          # Логирование
│       └── SystemInfo.hpp      # Системная информация
│
├── src/                        # Исходные файлы
│   ├── core/                   # Реализация core компонентов
│   ├── http/                   # Реализация HTTP слоя
│   ├── security/               # Реализация Schannel/TLS
│   ├── storage/                # Реализация хранилища
│   ├── handlers/               # Реализация обработчиков
│   ├── server/                 # Реализация HttpServer
│   ├── utils/                  # Утилиты
│   └── main.cpp                # Точка входа
│
├── tests/                      # Тесты
│   ├── CMakeLists.txt
│   ├── unit/                   # Юнит-тесты
│   │   ├── HttpParserTests.cpp
│   │   ├── HttpRouterTests.cpp
│   │   ├── HttpRequestTests.cpp
│   │   ├── HttpResponseTests.cpp
│   │   ├── HttpStatusTests.cpp
│   │   ├── ThreadSafeStoreTests.cpp
│   │   ├── InputValidationTests.cpp
│   │   ├── LoggerTests.cpp
│   │   ├── SystemInfoTests.cpp
│   │   ├── ErrorHandlerTests.cpp
│   │   ├── SchannelContextTests.cpp
│   │   ├── TlsConnectionTests.cpp
│   │   └── HttpsServerConfigTests.cpp
│   └── integration/            # Интеграционные тесты
│       └── ServerIntegrationTests.cpp
│
├── third_party/                # Внешние зависимости
│   └── nlohmann/
│       └── json.hpp            # JSON библиотека (header-only)
│
└── build/                      # Каталог сборки (создаётся CMake)
```

---

## Лицензия

MIT License

---

## Автор

Разработано как тестовое задание для позиции Senior C++ Developer (Сетевые технологии, TCP/HTTP).
