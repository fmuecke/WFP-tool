#include "dummy_proxy.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace dummy_proxy {
namespace {

struct Winsock {
    bool active{};
    Winsock() {
        WSADATA data{};
        active = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }
    ~Winsock() {
        if (active) {
            WSACleanup();
        }
    }
};

struct SocketCloser {
    void operator()(SOCKET* value) const noexcept {
        if (value && *value != INVALID_SOCKET) {
            closesocket(*value);
        }
        delete value;
    }
};
using UniqueSocket = std::unique_ptr<SOCKET, SocketCloser>;

struct HandleCloser {
    void operator()(HANDLE value) const noexcept {
        if (value && value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
        }
    }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

UniqueSocket make_socket(int family) {
    return UniqueSocket(new SOCKET(socket(family, SOCK_STREAM, IPPROTO_TCP)));
}

std::string lower(std::string_view value) {
    std::string result(value);
    std::ranges::transform(result, result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

std::string_view first_line(std::string_view request) {
    const auto end = request.find("\r\n");
    return request.substr(0, end);
}

std::optional<sandbox_network::Endpoint> parse_authority(
    std::string_view request) {
    const auto line = first_line(request);
    constexpr std::string_view prefix = "CONNECT ";
    if (!line.starts_with(prefix)) {
        return std::nullopt;
    }
    const auto version_separator = line.find(' ', prefix.size());
    if (version_separator == std::string_view::npos ||
        line.substr(version_separator + 1) != "HTTP/1.1") {
        return std::nullopt;
    }
    const auto authority =
        line.substr(prefix.size(), version_separator - prefix.size());
    const auto colon = authority.rfind(':');
    if (colon == std::string_view::npos || authority.find(':') != colon) {
        return std::nullopt;
    }
    const std::string hostname = lower(authority.substr(0, colon));
    if (hostname.empty()) {
        return std::nullopt;
    }
    IN_ADDR v4{};
    IN6_ADDR v6{};
    if (InetPtonA(AF_INET, hostname.c_str(), &v4) == 1 ||
        InetPtonA(AF_INET6, hostname.c_str(), &v6) == 1) {
        return std::nullopt;
    }
    unsigned int port{};
    const auto port_text = authority.substr(colon + 1);
    const auto [end, conversion_error] = std::from_chars(
        port_text.data(), port_text.data() + port_text.size(), port);
    if (conversion_error != std::errc{} ||
        end != port_text.data() + port_text.size() || port == 0 ||
        port > 65535) {
        return std::nullopt;
    }
    return sandbox_network::Endpoint{
        hostname, static_cast<std::uint16_t>(port)};
}

void log(
    const sandbox_network::Config& config, std::string_view event,
    std::string_view detail = {}) {
    std::ofstream stream(config.proxy_log, std::ios::app);
    if (!stream) {
        return;
    }
    const auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
    stream << timestamp << ' ' << event;
    if (!detail.empty()) {
        stream << ' ' << detail;
    }
    stream << '\n';
}

bool send_all(SOCKET socket, std::string_view response) {
    std::size_t sent{};
    while (sent < response.size()) {
        const int count = send(
            socket, response.data() + sent,
            static_cast<int>(response.size() - sent), 0);
        if (count == SOCKET_ERROR) {
            return false;
        }
        sent += static_cast<std::size_t>(count);
    }
    return true;
}

void handle_client(
    SOCKET client, const sandbox_network::Config& config) {
    UniqueSocket connection(new SOCKET(client));
    const DWORD timeout = 5'000;
    setsockopt(
        client, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    std::string request;
    std::array<char, 1024> buffer{};
    while (request.size() < 4096 && !request.contains("\r\n\r\n")) {
        const int received =
            recv(client, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (received <= 0) {
            break;
        }
        request.append(buffer.data(), static_cast<std::size_t>(received));
    }

    const auto authority = parse_authority(request);
    const bool allowed =
        authority &&
        std::ranges::find(config.allow, *authority) != config.allow.end();
    if (allowed) {
        log(
            config, "allow",
            authority->hostname + ":" + std::to_string(authority->port));
        send_all(client, "HTTP/1.1 200 Connection Established\r\n\r\n");
    } else {
        log(config, "deny", std::string(first_line(request)));
        send_all(
            client,
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n");
    }
}

UniqueSocket create_listener(int family, std::uint16_t port) {
    auto listener = make_socket(family);
    if (*listener == INVALID_SOCKET) {
        return listener;
    }
    const BOOL exclusive = TRUE;
    setsockopt(
        *listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

    sockaddr_storage address{};
    int address_size{};
    if (family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&address);
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address_size = sizeof(*v4);
    } else {
        const DWORD only_v6 = 1;
        setsockopt(
            *listener, IPPROTO_IPV6, IPV6_V6ONLY,
            reinterpret_cast<const char*>(&only_v6), sizeof(only_v6));
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&address);
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        v6->sin6_addr = in6addr_loopback;
        address_size = sizeof(*v6);
    }
    if (bind(
            *listener, reinterpret_cast<const sockaddr*>(&address),
            address_size) == SOCKET_ERROR ||
        listen(*listener, SOMAXCONN) == SOCKET_ERROR) {
        return UniqueSocket(new SOCKET(INVALID_SOCKET));
    }
    return listener;
}

std::wstring stop_event_name(std::uint16_t port) {
    return L"Global\\SandboxNetworkDummyProxy-" + std::to_wstring(port);
}

int serve(const sandbox_network::Config& config) {
    Winsock winsock;
    if (!winsock.active) {
        return 1;
    }
    auto v4 = create_listener(AF_INET, config.proxy_port);
    auto v6 = create_listener(AF_INET6, config.proxy_port);
    if (*v4 == INVALID_SOCKET || *v6 == INVALID_SOCKET) {
        return 1;
    }
    UniqueHandle stop(CreateEventW(
        nullptr, TRUE, FALSE, stop_event_name(config.proxy_port).c_str()));
    if (!stop) {
        return 1;
    }

    log(config, "start");
    while (WaitForSingleObject(stop.get(), 0) == WAIT_TIMEOUT) {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(*v4, &readable);
        FD_SET(*v6, &readable);
        timeval timeout{0, 250'000};
        const int ready = select(0, &readable, nullptr, nullptr, &timeout);
        if (ready == SOCKET_ERROR) {
            log(config, "error", "select");
            return 1;
        }
        for (const SOCKET listener : {*v4, *v6}) {
            if (FD_ISSET(listener, &readable)) {
                const SOCKET client = accept(listener, nullptr, nullptr);
                if (client != INVALID_SOCKET) {
                    handle_client(client, config);
                }
            }
        }
    }
    log(config, "stop");
    return 0;
}

std::wstring quote(std::wstring_view argument) {
    std::wstring result(1, L'"');
    std::size_t backslashes{};
    for (const wchar_t value : argument) {
        if (value == L'\\') {
            ++backslashes;
        } else if (value == L'"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(L'"');
            backslashes = 0;
        } else {
            result.append(backslashes, L'\\');
            backslashes = 0;
            result.push_back(value);
        }
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

std::optional<std::filesystem::path> executable_path() {
    std::wstring path(260, L'\0');
    for (;;) {
        const DWORD length =
            GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (!length) {
            return std::nullopt;
        }
        if (length < path.size() - 1) {
            path.resize(length);
            return std::filesystem::path(std::move(path));
        }
        path.resize(path.size() * 2);
    }
}

bool probe(
    int family, const sandbox_network::Config& config,
    std::string_view authority, int expected_status) {
    auto connection = make_socket(family);
    if (*connection == INVALID_SOCKET) {
        return false;
    }
    const DWORD timeout = 2'000;
    setsockopt(
        *connection, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(
        *connection, SOL_SOCKET, SO_SNDTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    sockaddr_storage address{};
    int address_size{};
    if (family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&address);
        v4->sin_family = AF_INET;
        v4->sin_port = htons(config.proxy_port);
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address_size = sizeof(*v4);
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&address);
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(config.proxy_port);
        v6->sin6_addr = in6addr_loopback;
        address_size = sizeof(*v6);
    }
    if (connect(
            *connection, reinterpret_cast<const sockaddr*>(&address),
            address_size) == SOCKET_ERROR) {
        return false;
    }
    const std::string request =
        "CONNECT " + std::string(authority) +
        " HTTP/1.1\r\nHost: " + std::string(authority) + "\r\n\r\n";
    if (!send_all(*connection, request)) {
        return false;
    }
    std::array<char, 128> response{};
    const int received =
        recv(*connection, response.data(), static_cast<int>(response.size()), 0);
    if (received <= 0) {
        return false;
    }
    const std::string expected =
        "HTTP/1.1 " + std::to_string(expected_status);
    return std::string_view(response.data(), static_cast<std::size_t>(received))
        .starts_with(expected);
}

bool verify(const sandbox_network::Config& config) {
    Winsock winsock;
    if (!winsock.active) {
        return false;
    }
    const std::string approved =
        config.approved_probe.hostname + ":" +
        std::to_string(config.approved_probe.port);
    return probe(AF_INET, config, approved, 200) &&
           probe(AF_INET6, config, approved, 200) &&
           probe(AF_INET, config, "127.0.0.1:443", 403) &&
           probe(AF_INET, config, "denied.invalid:443", 403);
}

int apply(
    const sandbox_network::Config& config,
    const std::filesystem::path& policy) {
    if (verify(config)) {
        return 0;
    }
    const auto executable = executable_path();
    if (!executable) {
        return 1;
    }
    std::wstring command =
        quote(executable->wstring()) + L" serve --policy " +
        quote(policy.wstring());
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(
            executable->c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, nullptr,
            executable->parent_path().c_str(), &startup, &process)) {
        return 1;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    for (int attempt = 0; attempt < 50; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (verify(config)) {
            return 0;
        }
    }
    UniqueHandle stop(OpenEventW(
        EVENT_MODIFY_STATE, FALSE, stop_event_name(config.proxy_port).c_str()));
    if (stop) {
        SetEvent(stop.get());
    }
    return 1;
}

int remove(const sandbox_network::Config& config) {
    UniqueHandle stop(OpenEventW(
        EVENT_MODIFY_STATE, FALSE, stop_event_name(config.proxy_port).c_str()));
    if (!stop) {
        return GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : 1;
    }
    if (!SetEvent(stop.get())) {
        return 1;
    }
    for (int attempt = 0; attempt < 50; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!verify(config)) {
            return 0;
        }
    }
    return 1;
}

void usage() {
    std::wcerr
        << L"Usage: dummy-proxy-adapter <apply|verify|remove> --policy <path>\n";
}

} // namespace

bool request_allowed(
    std::string_view request,
    std::span<const sandbox_network::Endpoint> allowlist) {
    const auto authority = parse_authority(request);
    return authority &&
           std::ranges::find(allowlist, *authority) != allowlist.end();
}

int run(std::span<const std::wstring_view> arguments) {
    if (arguments.size() != 3 || arguments[1] != L"--policy") {
        usage();
        return 2;
    }
    std::error_code path_error;
    const auto policy =
        std::filesystem::absolute(
            std::filesystem::path(arguments[2]), path_error);
    if (path_error) {
        std::wcerr << L"Error: cannot resolve policy path\n";
        return 2;
    }
    auto config = sandbox_network::load_config(policy);
    if (!config) {
        std::wcerr << L"Error: " << config.error().message << L'\n';
        return 2;
    }
    if (arguments[0] == L"serve") {
        return serve(*config);
    }
    if (arguments[0] == L"apply") {
        return apply(*config, policy);
    }
    if (arguments[0] == L"verify") {
        return verify(*config) ? 0 : 1;
    }
    if (arguments[0] == L"remove") {
        return remove(*config);
    }
    usage();
    return 2;
}

} // namespace dummy_proxy
