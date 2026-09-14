// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/user-net-lock.git

#include "user_net_lock.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iphlpapi.h>
#include <lm.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace
{

constexpr std::wstring_view proxy_port = L"49155";
constexpr std::wstring_view different_loopback_port = L"49156";
constexpr std::wstring_view blocked_non_loopback_port = L"49157";
constexpr std::wstring_view control_non_loopback_port = L"49158";
constexpr wchar_t traffic_password[] = L"WfpTraffic-Test-2026!";

int failures {};

void check(bool condition, std::string_view message)
{
    if (!condition)
    {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

bool is_elevated()
{
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators {};
    if (!AllocateAndInitializeSid(&authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &administrators))
    {
        return false;
    }
    BOOL member {};
    const BOOL checked = CheckTokenMembership(nullptr, administrators, &member);
    FreeSid(administrators);
    return checked && member != FALSE;
}

class Winsock
{
  public:
    Winsock() : status_(WSAStartup(MAKEWORD(2, 2), &data_)) {}
    ~Winsock()
    {
        if (status_ == 0)
        {
            WSACleanup();
        }
    }

    bool available() const { return status_ == 0; }

  private:
    WSADATA data_ {};
    int status_ {};
};

struct Receiver
{
    SOCKET socket {INVALID_SOCKET};
    std::thread worker;
    std::atomic<bool> received {};

    ~Receiver()
    {
        if (worker.joinable())
        {
            worker.join();
        }
        if (socket != INVALID_SOCKET)
        {
            closesocket(socket);
        }
    }
};

bool wait_for_readable(SOCKET socket)
{
    fd_set set;
    FD_ZERO(&set);
    FD_SET(socket, &set);
    timeval timeout {5, 0};
    return select(0, &set, nullptr, nullptr, &timeout) == 1;
}

bool start_tcp_receiver(Receiver& receiver, const sockaddr* address, int address_length)
{
    receiver.socket = socket(address->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (receiver.socket == INVALID_SOCKET)
    {
        return false;
    }
    if (address->sa_family == AF_INET6)
    {
        const DWORD v6_only = 1;
        if (setsockopt(receiver.socket,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                reinterpret_cast<const char*>(&v6_only),
                sizeof(v6_only)) == SOCKET_ERROR)
        {
            return false;
        }
    }
    if (bind(receiver.socket, address, address_length) == SOCKET_ERROR ||
        listen(receiver.socket, 1) == SOCKET_ERROR)
    {
        return false;
    }
    receiver.worker = std::thread(
        [&receiver]
        {
            if (!wait_for_readable(receiver.socket))
            {
                return;
            }
            const SOCKET client = accept(receiver.socket, nullptr, nullptr);
            if (client == INVALID_SOCKET)
            {
                return;
            }
            char marker {};
            receiver.received = recv(client, &marker, 1, 0) == 1 && marker == 'w';
            closesocket(client);
        });
    return true;
}

bool start_udp_receiver(Receiver& receiver, const sockaddr* address, int address_length)
{
    receiver.socket = socket(address->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (receiver.socket == INVALID_SOCKET ||
        bind(receiver.socket, address, address_length) == SOCKET_ERROR)
    {
        return false;
    }
    receiver.worker = std::thread(
        [&receiver]
        {
            if (!wait_for_readable(receiver.socket))
            {
                return;
            }
            char marker {};
            receiver.received = recv(receiver.socket, &marker, 1, 0) == 1 && marker == 'w';
        });
    return true;
}

bool receiver_received(Receiver& receiver)
{
    if (receiver.worker.joinable())
    {
        receiver.worker.join();
    }
    return receiver.received;
}

std::optional<sockaddr_in> non_loopback_address()
{
    ULONG size {};
    if (GetAdaptersAddresses(
            AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr, nullptr, &size) !=
        ERROR_BUFFER_OVERFLOW)
    {
        return std::nullopt;
    }
    std::vector<BYTE> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    if (GetAdaptersAddresses(
            AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr, adapters, &size) !=
        ERROR_SUCCESS)
    {
        return std::nullopt;
    }
    for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next)
    {
        if (adapter->OperStatus != IfOperStatusUp)
        {
            continue;
        }
        for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr;
            unicast = unicast->Next)
        {
            if (unicast->Address.lpSockaddr->sa_family != AF_INET)
            {
                continue;
            }
            const auto* candidate =
                reinterpret_cast<const sockaddr_in*>(unicast->Address.lpSockaddr);
            const ULONG address = ntohl(candidate->sin_addr.s_addr);
            if ((address >> 24) == 127 || (address >> 16) == 0xa9fe)
            {
                continue;
            }
            return *candidate;
        }
    }
    return std::nullopt;
}

bool parse_address(std::wstring_view text, std::uint16_t port, sockaddr_in& result)
{
    result = {};
    result.sin_family = AF_INET;
    result.sin_port = htons(port);
    return InetPtonW(AF_INET, std::wstring(text).c_str(), &result.sin_addr) == 1;
}

bool parse_address(std::wstring_view text, std::uint16_t port, sockaddr_in6& result)
{
    result = {};
    result.sin6_family = AF_INET6;
    result.sin6_port = htons(port);
    return InetPtonW(AF_INET6, std::wstring(text).c_str(), &result.sin6_addr) == 1;
}

int socket_probe(std::wstring_view protocol, std::wstring_view address, std::wstring_view port)
{
    addrinfoW hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = protocol == L"tcp" ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_protocol = protocol == L"tcp" ? IPPROTO_TCP : IPPROTO_UDP;
    addrinfoW* addresses {};
    if (GetAddrInfoW(
            std::wstring(address).c_str(), std::wstring(port).c_str(), &hints, &addresses) != 0)
    {
        return EXIT_FAILURE;
    }
    for (auto* candidate = addresses; candidate != nullptr; candidate = candidate->ai_next)
    {
        const SOCKET connection =
            socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (connection == INVALID_SOCKET)
        {
            continue;
        }
        const bool connected =
            connect(connection, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) !=
            SOCKET_ERROR;
        const char marker = 'w';
        const bool sent = connected && send(connection, &marker, 1, 0) == 1;
        closesocket(connection);
        if (sent)
        {
            FreeAddrInfoW(addresses);
            return EXIT_SUCCESS;
        }
    }
    FreeAddrInfoW(addresses);
    return EXIT_FAILURE;
}

int launch_probe(std::wstring_view user, std::wstring_view password, std::wstring_view protocol,
    std::wstring_view address, std::wstring_view port)
{
    std::array<wchar_t, MAX_PATH> executable {};
    const DWORD executable_length =
        GetModuleFileNameW(nullptr, executable.data(), executable.size());
    if (executable_length == 0 || executable_length == executable.size())
    {
        return EXIT_FAILURE;
    }
    std::wstring command = L"\"" + std::wstring(executable.data(), executable_length) +
                           L"\" --traffic-probe " + std::wstring(protocol) + L" " +
                           std::wstring(address) + L" " + std::wstring(port);
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process {};
    if (!CreateProcessWithLogonW(std::wstring(user).c_str(),
            L".",
            std::wstring(password).c_str(),
            LOGON_WITH_PROFILE,
            nullptr,
            mutable_command.data(),
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startup,
            &process))
    {
        return EXIT_FAILURE;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code {EXIT_FAILURE};
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(exit_code);
}

int run_user_port(std::wstring_view command, std::wstring_view user, std::wstring_view port)
{
    const std::array arguments {
        command, std::wstring_view(L"--user"), user, std::wstring_view(L"--port"), port
    };
    return user_net_lock::run(arguments);
}

int run_remove(std::wstring_view user)
{
    const std::array arguments {std::wstring_view(L"remove"), std::wstring_view(L"--user"), user};
    return user_net_lock::run(arguments);
}

bool set_test_password(std::wstring_view user)
{
    USER_INFO_1003 password {const_cast<wchar_t*>(traffic_password)};
    return NetUserSetInfo(nullptr,
               std::wstring(user).c_str(),
               1003,
               reinterpret_cast<LPBYTE>(&password),
               nullptr) == NERR_Success;
}

struct Cleanup
{
    std::wstring_view target;
    std::wstring_view other;
    ~Cleanup()
    {
        run_remove(target);
        run_remove(other);
    }
};

void traffic_enforcement_tests(std::wstring_view target, std::wstring_view other)
{
    Cleanup cleanup {target, other};
    check(run_remove(target) == static_cast<int>(user_net_lock::ExitCode::success),
        "remove any prior target policy");
    check(run_remove(other) == static_cast<int>(user_net_lock::ExitCode::success),
        "remove any prior control-account policy");
    check(set_test_password(target), "set disposable target-account password");
    check(set_test_password(other), "set disposable control-account password");
    check(run_user_port(L"apply", target, proxy_port) ==
              static_cast<int>(user_net_lock::ExitCode::success),
        "apply target loopback policy");

    Winsock winsock;
    check(winsock.available(), "start Winsock");
    if (!winsock.available())
    {
        return;
    }
    sockaddr_in loopback_v4 {};
    sockaddr_in6 loopback_v6 {};
    check(parse_address(L"127.0.0.1", 49155, loopback_v4), "parse IPv4 loopback address");
    check(parse_address(L"::1", 49155, loopback_v6), "parse IPv6 loopback address");
    const auto non_loopback = non_loopback_address();
    check(non_loopback.has_value(), "find a non-loopback IPv4 address");
    if (failures != 0 || !non_loopback)
    {
        return;
    }

    sockaddr_in blocked_address = *non_loopback;
    blocked_address.sin_port = htons(49157);
    sockaddr_in control_address = *non_loopback;
    control_address.sin_port = htons(49158);
    Receiver loopback_v4_receiver;
    Receiver loopback_v6_receiver;
    Receiver different_loopback_tcp_receiver;
    Receiver different_loopback_udp_receiver;
    Receiver blocked_tcp_receiver;
    Receiver blocked_udp_receiver;
    Receiver control_tcp_receiver;
    Receiver control_udp_receiver;
    check(start_tcp_receiver(loopback_v4_receiver,
              reinterpret_cast<const sockaddr*>(&loopback_v4),
              sizeof(loopback_v4)),
        "start IPv4 loopback TCP listener");
    check(start_tcp_receiver(loopback_v6_receiver,
              reinterpret_cast<const sockaddr*>(&loopback_v6),
              sizeof(loopback_v6)),
        "start IPv6 loopback TCP listener");
    sockaddr_in different_loopback_address = loopback_v4;
    different_loopback_address.sin_port = htons(49156);
    check(start_tcp_receiver(different_loopback_tcp_receiver,
              reinterpret_cast<const sockaddr*>(&different_loopback_address),
              sizeof(different_loopback_address)),
        "start different-loopback TCP listener");
    check(start_udp_receiver(different_loopback_udp_receiver,
              reinterpret_cast<const sockaddr*>(&different_loopback_address),
              sizeof(different_loopback_address)),
        "start different-loopback UDP listener");
    // The runner starts a fresh Windows Sandbox guest for every test run, so
    // there are no retained guest Windows Firewall rules to affect these
    // non-loopback control listeners.
    check(start_tcp_receiver(blocked_tcp_receiver,
              reinterpret_cast<const sockaddr*>(&blocked_address),
              sizeof(blocked_address)),
        "start blocked-path TCP listener");
    check(start_udp_receiver(blocked_udp_receiver,
              reinterpret_cast<const sockaddr*>(&blocked_address),
              sizeof(blocked_address)),
        "start blocked-path UDP listener");
    check(start_tcp_receiver(control_tcp_receiver,
              reinterpret_cast<const sockaddr*>(&control_address),
              sizeof(control_address)),
        "start control-account TCP listener");
    check(start_udp_receiver(control_udp_receiver,
              reinterpret_cast<const sockaddr*>(&control_address),
              sizeof(control_address)),
        "start control-account UDP listener");
    if (failures != 0)
    {
        return;
    }

    const auto failed =
        [&](std::wstring_view protocol, std::wstring_view address, std::wstring_view port)
    { return launch_probe(target, traffic_password, protocol, address, port) != EXIT_SUCCESS; };
    wchar_t non_loopback_text[INET_ADDRSTRLEN] {};
    check(
        InetNtopW(AF_INET, &non_loopback->sin_addr, non_loopback_text, INET_ADDRSTRLEN) != nullptr,
        "format non-loopback IPv4 address");
    if (failures != 0)
    {
        return;
    }
    const std::wstring_view non_loopback_view(non_loopback_text);

    check(launch_probe(target, traffic_password, L"tcp", L"127.0.0.1", proxy_port) == EXIT_SUCCESS,
        "target process reaches configured IPv4 loopback proxy port");
    check(launch_probe(target, traffic_password, L"tcp", L"::1", proxy_port) == EXIT_SUCCESS,
        "target process reaches configured IPv6 loopback proxy port");
    check(failed(L"tcp", L"127.0.0.1", different_loopback_port),
        "target process is blocked from a different loopback TCP port");
    // UDP send can report local queueing success even when ALE later drops the
    // datagram. The receiver is the end-to-end enforcement assertion below.
    launch_probe(target, traffic_password, L"udp", L"127.0.0.1", different_loopback_port);
    check(failed(L"tcp", non_loopback_view, blocked_non_loopback_port),
        "target process is blocked from non-loopback TCP");
    launch_probe(target, traffic_password, L"udp", non_loopback_view, blocked_non_loopback_port);
    check(launch_probe(
              other, traffic_password, L"tcp", non_loopback_view, control_non_loopback_port) ==
              EXIT_SUCCESS,
        "control account reaches non-loopback TCP");
    check(launch_probe(
              other, traffic_password, L"udp", non_loopback_view, control_non_loopback_port) ==
              EXIT_SUCCESS,
        "control account reaches non-loopback UDP");

    check(
        receiver_received(loopback_v4_receiver), "IPv4 loopback listener received target traffic");
    check(
        receiver_received(loopback_v6_receiver), "IPv6 loopback listener received target traffic");
    check(!receiver_received(different_loopback_tcp_receiver),
        "different-loopback TCP listener received no target traffic");
    check(!receiver_received(different_loopback_udp_receiver),
        "different-loopback UDP listener received no target traffic");
    check(!receiver_received(blocked_tcp_receiver),
        "blocked TCP listener received no target traffic");
    check(!receiver_received(blocked_udp_receiver),
        "blocked UDP listener received no target traffic");
    check(receiver_received(control_tcp_receiver), "control TCP listener received traffic");
    check(receiver_received(control_udp_receiver), "control UDP listener received traffic");
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    Winsock winsock;
    if (argc == 5 && std::wstring_view(argv[1]) == L"--traffic-probe")
    {
        return winsock.available() ? socket_probe(argv[2], argv[3], argv[4]) : EXIT_FAILURE;
    }
    if (argc != 3)
    {
        std::wcerr << L"Usage: user-net-lock-traffic-integration-tests <target-account> "
                      L"<control-account>\n";
        return EXIT_FAILURE;
    }
    if (!is_elevated())
    {
        std::wcerr << L"This integration test requires an elevated Administrator session.\n";
        return EXIT_FAILURE;
    }
    if (std::wstring_view(argv[1]) == argv[2])
    {
        std::wcerr << L"The integration test requires two different disposable accounts.\n";
        return EXIT_FAILURE;
    }
    traffic_enforcement_tests(argv[1], argv[2]);
    if (failures != 0)
    {
        return EXIT_FAILURE;
    }
    std::cout << "WFP traffic enforcement integration tests passed\n";
    return EXIT_SUCCESS;
}
