#include "sandbox_network.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <aclapi.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <tcpmib.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <system_error>
#include <tuple>
#include <utility>

namespace sandbox_network {
namespace {

constexpr GUID provider_key{
    0x8809307e, 0xe2b2, 0x4d8b, {0x95, 0x41, 0x47, 0x50, 0x39, 0xb7, 0xf0, 0xdf}};
constexpr GUID sublayer_key{
    0x22fac16c, 0xe5f1, 0x43d7, {0x8a, 0x67, 0x08, 0x2d, 0x41, 0xce, 0x61, 0x58}};
constexpr GUID permit_v4_key{
    0xb546bb36, 0x00a3, 0x4c50, {0x90, 0x54, 0x4c, 0x2f, 0xf7, 0xd0, 0x36, 0xfd}};
constexpr GUID permit_v6_key{
    0xc3bca89e, 0x2777, 0x4851, {0x83, 0x4a, 0x42, 0x31, 0xae, 0xf7, 0xec, 0x8b}};
constexpr GUID permit_v6_mapped_key{
    0x5de389a8, 0xeaae, 0x4983, {0xad, 0xfc, 0xd4, 0x59, 0xaa, 0xe6, 0x28, 0xa4}};
constexpr GUID block_v4_key{
    0xd642bd8d, 0x64ca, 0x4eae, {0xb3, 0xbc, 0x37, 0x3b, 0x05, 0x23, 0xee, 0xa3}};
constexpr GUID block_v6_key{
    0xe96806e1, 0x309b, 0x416b, {0x93, 0xaf, 0x1a, 0x98, 0x37, 0x2d, 0x55, 0xaa}};

constexpr std::uint64_t permit_weight = 0xF000000000000000ULL;
constexpr std::uint64_t block_weight = 0x1000000000000000ULL;
constexpr std::uint16_t sublayer_weight = 0x8000;
constexpr DWORD adapter_timeout_ms = 60'000;

using LocalMemory = std::unique_ptr<void, decltype(&LocalFree)>;

struct HandleCloser {
    void operator()(HANDLE handle) const noexcept {
        if (handle && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

struct Engine {
    HANDLE value{};
    ~Engine() {
        if (value) {
            FwpmEngineClose0(value);
        }
    }
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    Engine() = default;
    Engine(Engine&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Engine& operator=(Engine&& other) noexcept {
        if (this != &other) {
            if (value) {
                FwpmEngineClose0(value);
            }
            value = std::exchange(other.value, nullptr);
        }
        return *this;
    }
};

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

Error error(ExitCode exit_code, std::uint32_t native_code, std::wstring message) {
    return Error{exit_code, native_code, std::move(message)};
}

std::wstring system_message(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    LocalMemory memory(buffer, LocalFree);
    if (!length) {
        return L"error " + std::to_wstring(code);
    }
    std::wstring text(buffer, length);
    while (!text.empty() && std::iswspace(text.back())) {
        text.pop_back();
    }
    return text;
}

Error win32_error(ExitCode exit_code, DWORD code, std::wstring_view operation) {
    return error(
        exit_code, code,
        std::wstring(operation) + L": " + system_message(code) +
            L" (" + std::to_wstring(code) + L")");
}

std::string_view trim(std::string_view text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
        text.remove_suffix(1);
    }
    return text;
}

std::string ascii_lower(std::string_view text) {
    std::string result(text);
    std::ranges::transform(result, result.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return result;
}

Result<std::wstring> utf8_to_wide(std::string_view text) {
    if (text.empty()) {
        return std::wstring{};
    }
    const int size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
        nullptr, 0);
    if (!size) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::usage_or_config, code, L"Invalid UTF-8 configuration"));
    }
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    if (!MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
            static_cast<int>(text.size()), result.data(), size)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::usage_or_config, code, L"Invalid UTF-8 configuration"));
    }
    return result;
}

Result<std::uint16_t> parse_port(std::string_view text) {
    unsigned int value{};
    const auto [end, conversion_error] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (conversion_error != std::errc{} || end != text.data() + text.size() ||
        value == 0 || value > 65535) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_INVALID_DATA,
            L"Port must be an integer from 1 through 65535"));
    }
    return static_cast<std::uint16_t>(value);
}

Result<std::uint32_t> parse_version(std::string_view text) {
    std::uint32_t value{};
    const auto [end, conversion_error] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (conversion_error != std::errc{} || end != text.data() + text.size() ||
        value == 0) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_INVALID_DATA,
            L"policy_version must be a positive integer"));
    }
    return value;
}

bool is_ip_literal(std::string_view hostname) {
    IN_ADDR v4{};
    IN6_ADDR v6{};
    const std::string value(hostname);
    return InetPtonA(AF_INET, value.c_str(), &v4) == 1 ||
           InetPtonA(AF_INET6, value.c_str(), &v6) == 1;
}

bool is_valid_hostname(std::string_view hostname) {
    if (hostname.empty() || hostname.size() > 253 || hostname.contains('*') ||
        is_ip_literal(hostname) || !hostname.contains('.') ||
        hostname.front() == '.' || hostname.back() == '.' ||
        !std::ranges::any_of(hostname, [](unsigned char value) {
            return std::isalpha(value);
        })) {
        return false;
    }

    std::size_t start = 0;
    while (start < hostname.size()) {
        const std::size_t dot = hostname.find('.', start);
        const std::size_t end = dot == std::string_view::npos ? hostname.size() : dot;
        const auto label = hostname.substr(start, end - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' ||
            label.back() == '-') {
            return false;
        }
        if (!std::ranges::all_of(label, [](unsigned char value) {
                return std::isalnum(value) || value == '-';
            })) {
            return false;
        }
        if (dot == std::string_view::npos) {
            break;
        }
        start = dot + 1;
    }
    return true;
}

Result<Endpoint> parse_endpoint(std::string_view text) {
    const std::size_t separator = text.rfind(':');
    if (separator == std::string_view::npos) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_INVALID_DATA,
            L"Endpoint must be hostname:port"));
    }
    const std::string hostname = ascii_lower(trim(text.substr(0, separator)));
    if (!is_valid_hostname(hostname)) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_INVALID_DATA,
            L"Endpoint contains an invalid hostname"));
    }
    auto port = parse_port(trim(text.substr(separator + 1)));
    if (!port) {
        return std::unexpected(port.error());
    }
    return Endpoint{hostname, *port};
}

Result<void> validate_config(const Config& config) {
    if (config.account.empty()) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_INVALID_DATA,
            L"policy.account is required"));
    }
    if (!config.proxy_adapter.is_absolute() || !config.proxy_log.is_absolute()) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_INVALID_DATA,
            L"proxy_adapter and proxy_log must be absolute paths"));
    }
    if (config.allow.empty()) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_INVALID_DATA,
            L"At least one exact hostname must be allowed"));
    }
    if (std::ranges::find(config.allow, config.approved_probe) == config.allow.end()) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_INVALID_DATA,
            L"probe.approved must also appear in the allow section"));
    }
    return {};
}

Result<std::filesystem::path> environment_path(const wchar_t* name) {
    SetLastError(ERROR_SUCCESS);
    const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (!required) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::precondition, code ? code : ERROR_ENVVAR_NOT_FOUND,
            std::wstring(L"Read environment variable ") + name));
    }
    std::wstring value(required, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), required);
    if (!written || written >= required) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::precondition, code, std::wstring(L"Read environment variable ") + name));
    }
    value.resize(written);
    return std::filesystem::path(std::move(value));
}

bool path_has_prefix(
    const std::filesystem::path& path, const std::filesystem::path& prefix) {
    std::error_code path_error;
    const auto full_path = std::filesystem::weakly_canonical(path, path_error);
    if (path_error) {
        return false;
    }
    const auto full_prefix = std::filesystem::weakly_canonical(prefix, path_error);
    if (path_error) {
        return false;
    }
    std::wstring path_text = full_path.native();
    std::wstring prefix_text = full_prefix.native();
    std::ranges::transform(path_text, path_text.begin(), [](wchar_t value) {
        return static_cast<wchar_t>(std::towlower(value));
    });
    std::ranges::transform(prefix_text, prefix_text.begin(), [](wchar_t value) {
        return static_cast<wchar_t>(std::towlower(value));
    });
    if (!prefix_text.ends_with(L'\\')) {
        prefix_text.push_back(L'\\');
    }
    return path_text.starts_with(prefix_text);
}

Result<void> validate_adapter_path(const std::filesystem::path& adapter) {
    const DWORD attributes = GetFileAttributesW(adapter.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        const DWORD code = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_DIRECTORY;
        return std::unexpected(win32_error(
            ExitCode::usage_or_config, code, L"Proxy adapter is not a file"));
    }

    auto program_files = environment_path(L"ProgramFiles");
    if (!program_files) {
        return std::unexpected(program_files.error());
    }
    bool protected_location = path_has_prefix(adapter, *program_files);
    auto program_files_x86 = environment_path(L"ProgramFiles(x86)");
    if (program_files_x86) {
        protected_location =
            protected_location || path_has_prefix(adapter, *program_files_x86);
    }
    auto program_data = environment_path(L"ProgramData");
    if (program_data) {
        protected_location =
            protected_location || path_has_prefix(adapter, *program_data);
    }
    if (!protected_location) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_ACCESS_DENIED,
            L"Proxy adapter must be installed below Program Files or ProgramData"));
    }
    return {};
}

Result<bool> is_elevated() {
    HANDLE raw_token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::precondition, code, L"Open current process token"));
    }
    UniqueHandle token(raw_token);
    TOKEN_ELEVATION elevation{};
    DWORD size{};
    if (!GetTokenInformation(
            token.get(), TokenElevation, &elevation, sizeof(elevation), &size)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::precondition, code, L"Read token elevation"));
    }
    return elevation.TokenIsElevated != 0;
}

Result<void> require_elevation() {
    auto elevated = is_elevated();
    if (!elevated) {
        return std::unexpected(elevated.error());
    }
    if (!*elevated) {
        return std::unexpected(error(
            ExitCode::precondition, ERROR_ELEVATION_REQUIRED,
            L"This command requires an elevated administrator token"));
    }
    return {};
}

Result<std::vector<std::byte>> resolve_account_sid(std::wstring_view account) {
    DWORD sid_size{};
    DWORD domain_size{};
    SID_NAME_USE use{};
    std::wstring account_name(account);
    LookupAccountNameW(
        nullptr, account_name.c_str(), nullptr, &sid_size, nullptr, &domain_size, &use);
    DWORD code = GetLastError();
    if (code != ERROR_INSUFFICIENT_BUFFER) {
        return std::unexpected(win32_error(
            ExitCode::usage_or_config, code, L"Resolve sandbox account"));
    }

    std::vector<std::byte> sid(sid_size);
    std::wstring domain(domain_size, L'\0');
    if (!LookupAccountNameW(
            nullptr, account_name.c_str(), sid.data(), &sid_size, domain.data(),
            &domain_size, &use)) {
        code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::usage_or_config, code, L"Resolve sandbox account"));
    }
    if (!IsValidSid(sid.data())) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_INVALID_SID,
            L"Resolved sandbox account has an invalid SID"));
    }
    return sid;
}

Result<std::wstring> sid_string(PSID sid) {
    wchar_t* raw{};
    if (!ConvertSidToStringSidW(sid, &raw)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Convert account SID"));
    }
    LocalMemory memory(raw, LocalFree);
    return std::wstring(raw);
}

Result<std::vector<std::byte>> security_descriptor(std::wstring_view sddl) {
    PSECURITY_DESCRIPTOR raw{};
    ULONG size{};
    std::wstring value(sddl);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            value.c_str(), SDDL_REVISION_1, &raw, &size)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Create security descriptor"));
    }
    LocalMemory memory(raw, LocalFree);
    const auto* begin = static_cast<const std::byte*>(raw);
    return std::vector<std::byte>(begin, begin + size);
}

Result<std::vector<std::byte>> user_condition_descriptor(PSID sid) {
    auto text = sid_string(sid);
    if (!text) {
        return std::unexpected(text.error());
    }
    return security_descriptor(L"D:(A;;0x00000001;;;" + *text + L")");
}

Result<std::vector<std::byte>> wfp_object_descriptor() {
    return security_descriptor(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)");
}

Result<Engine> open_engine(ExitCode exit_code = ExitCode::wfp) {
    Engine engine;
    FWPM_SESSION0 session{};
    session.displayData.name =
        const_cast<wchar_t*>(L"Sandbox Network Policy Session");
    session.txnWaitTimeoutInMSec = 15'000;
    const DWORD code = FwpmEngineOpen0(
        nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine.value);
    if (code != ERROR_SUCCESS) {
        return std::unexpected(win32_error(
            exit_code, code, L"Open Windows Filtering Platform engine"));
    }
    return engine;
}

} // namespace

Result<Config> parse_config(std::string_view text) {
    Config config{};
    std::optional<std::string> account;
    std::optional<std::string> adapter;
    std::optional<std::string> log;
    std::optional<std::uint32_t> version;
    std::optional<std::uint16_t> proxy_port;
    std::optional<Endpoint> approved;
    std::set<Endpoint, bool (*)(const Endpoint&, const Endpoint&)> unique_allow(
        [](const Endpoint& left, const Endpoint& right) {
            return std::tie(left.hostname, left.port) <
                   std::tie(right.hostname, right.port);
        });

    std::string section;
    std::size_t line_number = 0;
    while (!text.empty()) {
        ++line_number;
        const std::size_t newline = text.find('\n');
        std::string_view line =
            trim(text.substr(0, newline == std::string_view::npos ? text.size() : newline));
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
            line = trim(line);
        }
        if (newline == std::string_view::npos) {
            text = {};
        } else {
            text.remove_prefix(newline + 1);
        }
        if (line.empty() || line.front() == '#' || line.front() == ';') {
            continue;
        }
        if (line.front() == '[' && line.back() == ']') {
            section = ascii_lower(trim(line.substr(1, line.size() - 2)));
            if (section != "policy" && section != "allow" && section != "probe") {
                return std::unexpected(error(
                    ExitCode::usage_or_config, ERROR_INVALID_DATA,
                    L"Unknown configuration section on line " +
                        std::to_wstring(line_number)));
            }
            continue;
        }

        const std::size_t equals = line.find('=');
        if (equals == std::string_view::npos || section.empty()) {
            return std::unexpected(error(
                ExitCode::usage_or_config, ERROR_INVALID_DATA,
                L"Expected key=value on line " + std::to_wstring(line_number)));
        }
        const std::string key = ascii_lower(trim(line.substr(0, equals)));
        const std::string_view value = trim(line.substr(equals + 1));
        if (key.empty() || value.empty()) {
            return std::unexpected(error(
                ExitCode::usage_or_config, ERROR_INVALID_DATA,
                L"Empty key or value on line " + std::to_wstring(line_number)));
        }

        if (section == "policy") {
            if (key == "account" && !account) {
                account = std::string(value);
            } else if (key == "policy_version" && !version) {
                auto parsed = parse_version(value);
                if (!parsed) {
                    return std::unexpected(parsed.error());
                }
                version = *parsed;
            } else if (key == "proxy_port" && !proxy_port) {
                auto parsed = parse_port(value);
                if (!parsed) {
                    return std::unexpected(parsed.error());
                }
                proxy_port = *parsed;
            } else if (key == "proxy_adapter" && !adapter) {
                adapter = std::string(value);
            } else if (key == "proxy_log" && !log) {
                log = std::string(value);
            } else {
                return std::unexpected(error(
                    ExitCode::usage_or_config, ERROR_INVALID_DATA,
                    L"Unknown or duplicate policy key on line " +
                        std::to_wstring(line_number)));
            }
        } else if (section == "allow") {
            const std::string hostname = ascii_lower(key);
            if (!is_valid_hostname(hostname)) {
                return std::unexpected(error(
                    ExitCode::usage_or_config, ERROR_INVALID_DATA,
                    L"Invalid allowlist hostname on line " +
                        std::to_wstring(line_number)));
            }
            auto port = parse_port(value);
            if (!port) {
                return std::unexpected(port.error());
            }
            if (!unique_allow.emplace(Endpoint{hostname, *port}).second) {
                return std::unexpected(error(
                    ExitCode::usage_or_config, ERROR_INVALID_DATA,
                    L"Duplicate allowlist entry on line " +
                        std::to_wstring(line_number)));
            }
        } else if (key == "approved" && !approved) {
            auto endpoint = parse_endpoint(value);
            if (!endpoint) {
                return std::unexpected(endpoint.error());
            }
            approved = *endpoint;
        } else {
            return std::unexpected(error(
                ExitCode::usage_or_config, ERROR_INVALID_DATA,
                L"Unknown or duplicate probe key on line " +
                    std::to_wstring(line_number)));
        }
    }

    if (!account || !version || !proxy_port || !adapter || !log || !approved) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_INVALID_DATA,
            L"Configuration is missing a required key"));
    }
    auto wide_account = utf8_to_wide(*account);
    auto wide_adapter = utf8_to_wide(*adapter);
    auto wide_log = utf8_to_wide(*log);
    if (!wide_account) {
        return std::unexpected(wide_account.error());
    }
    if (!wide_adapter) {
        return std::unexpected(wide_adapter.error());
    }
    if (!wide_log) {
        return std::unexpected(wide_log.error());
    }

    config.account = std::move(*wide_account);
    config.policy_version = *version;
    config.proxy_port = *proxy_port;
    config.proxy_adapter = std::move(*wide_adapter);
    config.proxy_log = std::move(*wide_log);
    config.allow.assign(unique_allow.begin(), unique_allow.end());
    config.approved_probe = std::move(*approved);
    auto valid = validate_config(config);
    if (!valid) {
        return std::unexpected(valid.error());
    }
    return config;
}

Result<Config> load_config(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_FILE_NOT_FOUND,
            L"Cannot open configuration: " + path.wstring()));
    }
    std::ostringstream text;
    text << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_READ_FAULT,
            L"Cannot read configuration: " + path.wstring()));
    }
    return parse_config(text.str());
}

std::filesystem::path installed_policy_path() {
    auto program_data = environment_path(L"ProgramData");
    if (!program_data) {
        return L"C:\\ProgramData\\SandboxNetwork\\policy.ini";
    }
    return *program_data / L"SandboxNetwork" / L"policy.ini";
}

namespace {

Result<void> set_path_security(
    const std::filesystem::path& path, std::wstring_view sddl) {
    PSECURITY_DESCRIPTOR raw{};
    std::wstring descriptor_text(sddl);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.c_str(), SDDL_REVISION_1, &raw, nullptr)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::precondition, code, L"Create filesystem security descriptor"));
    }
    LocalMemory descriptor(raw, LocalFree);
    if (!SetFileSecurityW(
            path.c_str(),
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION,
            raw)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::precondition, code, L"Protect " + path.wstring()));
    }
    return {};
}

Result<void> protect_managed_adapter(const std::filesystem::path& adapter) {
    if (!path_has_prefix(adapter, installed_policy_path().parent_path())) {
        return {};
    }
    return set_path_security(
        adapter, L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)");
}

Result<Config> install_config_file(
    const std::filesystem::path& source, bool replace_existing) {
    auto parsed = load_config(source);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    auto adapter_valid = validate_adapter_path(parsed->proxy_adapter);
    if (!adapter_valid) {
        return std::unexpected(adapter_valid.error());
    }
    auto sid = resolve_account_sid(parsed->account);
    if (!sid) {
        return std::unexpected(sid.error());
    }

    const auto destination = installed_policy_path();
    const DWORD existing = GetFileAttributesW(destination.c_str());
    if (!replace_existing && existing != INVALID_FILE_ATTRIBUTES) {
        return std::unexpected(error(
            ExitCode::usage_or_config, ERROR_ALREADY_EXISTS,
            L"Policy is already installed; use repair"));
    }

    std::error_code filesystem_error;
    std::filesystem::create_directories(destination.parent_path(), filesystem_error);
    if (filesystem_error) {
        return std::unexpected(error(
            ExitCode::precondition, static_cast<std::uint32_t>(filesystem_error.value()),
            L"Create policy directory: " + destination.parent_path().wstring()));
    }
    auto protected_directory = set_path_security(
        destination.parent_path(),
        L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)");
    if (!protected_directory) {
        return std::unexpected(protected_directory.error());
    }
    auto protected_adapter = protect_managed_adapter(parsed->proxy_adapter);
    if (!protected_adapter) {
        return std::unexpected(protected_adapter.error());
    }

    std::filesystem::path source_full =
        std::filesystem::weakly_canonical(source, filesystem_error);
    if (filesystem_error) {
        return std::unexpected(error(
            ExitCode::usage_or_config,
            static_cast<std::uint32_t>(filesystem_error.value()),
            L"Resolve source policy path"));
    }
    std::filesystem::path destination_full =
        std::filesystem::weakly_canonical(destination, filesystem_error);
    const bool same_file = !filesystem_error &&
                           _wcsicmp(
                               source_full.c_str(), destination_full.c_str()) == 0;
    if (!same_file) {
        const auto temporary = destination.wstring() + L".new";
        if (!CopyFileW(source.c_str(), temporary.c_str(), FALSE)) {
            const DWORD code = GetLastError();
            return std::unexpected(win32_error(
                ExitCode::precondition, code, L"Stage installed policy"));
        }
        auto protected_file = set_path_security(
            temporary, L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)");
        if (!protected_file) {
            DeleteFileW(temporary.c_str());
            return std::unexpected(protected_file.error());
        }
        if (!MoveFileExW(
                temporary.c_str(), destination.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            const DWORD code = GetLastError();
            DeleteFileW(temporary.c_str());
            return std::unexpected(win32_error(
                ExitCode::precondition, code, L"Install policy"));
        }
    } else {
        auto protected_file = set_path_security(
            destination, L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)");
        if (!protected_file) {
            return std::unexpected(protected_file.error());
        }
    }
    return load_config(destination);
}

std::wstring quote_argument(std::wstring_view argument) {
    if (argument.empty()) {
        return L"\"\"";
    }
    if (!argument.contains(L' ') && !argument.contains(L'\t') &&
        !argument.contains(L'"')) {
        return std::wstring(argument);
    }

    std::wstring result(1, L'"');
    std::size_t backslashes = 0;
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

Result<void> run_adapter(const Config& config, std::wstring_view verb) {
    auto valid = validate_adapter_path(config.proxy_adapter);
    if (!valid) {
        return std::unexpected(valid.error());
    }

    std::wstring command_line =
        quote_argument(config.proxy_adapter.wstring()) + L" " +
        std::wstring(verb) + L" --policy " +
        quote_argument(installed_policy_path().wstring());
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    std::wstring working_directory = config.proxy_adapter.parent_path().wstring();
    if (!CreateProcessW(
            config.proxy_adapter.c_str(), command_line.data(), nullptr, nullptr, FALSE,
            0, nullptr, working_directory.c_str(), &startup, &process)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::proxy, code, L"Start proxy adapter"));
    }
    UniqueHandle process_handle(process.hProcess);
    UniqueHandle thread_handle(process.hThread);

    const DWORD wait = WaitForSingleObject(process_handle.get(), adapter_timeout_ms);
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(process_handle.get(), ERROR_TIMEOUT);
        WaitForSingleObject(process_handle.get(), 5'000);
        return std::unexpected(error(
            ExitCode::proxy, ERROR_TIMEOUT,
            L"Proxy adapter timed out during " + std::wstring(verb)));
    }
    if (wait != WAIT_OBJECT_0) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::proxy, code, L"Wait for proxy adapter"));
    }
    DWORD exit_code{};
    if (!GetExitCodeProcess(process_handle.get(), &exit_code)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::proxy, code, L"Read proxy adapter exit code"));
    }
    if (exit_code != 0) {
        return std::unexpected(error(
            ExitCode::proxy, exit_code,
            L"Proxy adapter " + std::wstring(verb) + L" failed with exit code " +
                std::to_wstring(exit_code)));
    }
    return {};
}

Result<std::vector<std::byte>> tcp_table(ULONG family) {
    ULONG size{};
    DWORD code = GetExtendedTcpTable(
        nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (code != ERROR_INSUFFICIENT_BUFFER) {
        return std::unexpected(win32_error(
            ExitCode::proxy, code, L"Size TCP listener table"));
    }
    std::vector<std::byte> table(size);
    code = GetExtendedTcpTable(
        table.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (code != NO_ERROR) {
        return std::unexpected(win32_error(
            ExitCode::proxy, code, L"Read TCP listener table"));
    }
    return table;
}

Result<void> verify_proxy_listeners(std::uint16_t port) {
    auto v4_data = tcp_table(AF_INET);
    if (!v4_data) {
        return std::unexpected(v4_data.error());
    }
    auto v6_data = tcp_table(AF_INET6);
    if (!v6_data) {
        return std::unexpected(v6_data.error());
    }

    bool found_v4 = false;
    const auto* v4 = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(v4_data->data());
    for (DWORD index = 0; index < v4->dwNumEntries; ++index) {
        const auto& row = v4->table[index];
        if (ntohs(static_cast<u_short>(row.dwLocalPort)) != port) {
            continue;
        }
        if (row.dwLocalAddr != htonl(INADDR_LOOPBACK)) {
            return std::unexpected(error(
                ExitCode::proxy, ERROR_ACCESS_DENIED,
                L"Proxy port has a non-loopback IPv4 listener"));
        }
        found_v4 = true;
    }

    bool found_v6 = false;
    const auto* v6 = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(v6_data->data());
    for (DWORD index = 0; index < v6->dwNumEntries; ++index) {
        const auto& row = v6->table[index];
        if (ntohs(static_cast<u_short>(row.dwLocalPort)) != port) {
            continue;
        }
        IN6_ADDR address{};
        std::memcpy(address.u.Byte, row.ucLocalAddr, sizeof(address.u.Byte));
        if (!IN6_IS_ADDR_LOOPBACK(&address)) {
            return std::unexpected(error(
                ExitCode::proxy, ERROR_ACCESS_DENIED,
                L"Proxy port has a non-loopback IPv6 listener"));
        }
        found_v6 = true;
    }
    if (!found_v4 || !found_v6) {
        return std::unexpected(error(
            ExitCode::proxy, ERROR_NOT_READY,
            L"Proxy must listen on both 127.0.0.1 and ::1"));
    }
    return {};
}

struct SocketCloser {
    void operator()(SOCKET* value) const noexcept {
        if (value && *value != INVALID_SOCKET) {
            closesocket(*value);
        }
        delete value;
    }
};
using UniqueSocket = std::unique_ptr<SOCKET, SocketCloser>;

UniqueSocket make_socket(int family, int type, int protocol) {
    return UniqueSocket(new SOCKET(socket(family, type, protocol)));
}

Result<void> verify_approved_connect(const Config& config) {
    Winsock winsock;
    if (!winsock.active) {
        return std::unexpected(error(
            ExitCode::proxy, WSAGetLastError(), L"Initialize Winsock"));
    }
    auto connection = make_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*connection == INVALID_SOCKET) {
        const int code = WSAGetLastError();
        return std::unexpected(error(
            ExitCode::proxy, static_cast<std::uint32_t>(code),
            L"Create proxy probe socket"));
    }
    const DWORD timeout = 10'000;
    setsockopt(
        *connection, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(
        *connection, SOL_SOCKET, SO_SNDTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config.proxy_port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(
            *connection, reinterpret_cast<const sockaddr*>(&address),
            sizeof(address)) == SOCKET_ERROR) {
        const int code = WSAGetLastError();
        return std::unexpected(error(
            ExitCode::proxy, static_cast<std::uint32_t>(code),
            L"Connect to loopback proxy"));
    }

    const std::string authority =
        config.approved_probe.hostname + ":" +
        std::to_string(config.approved_probe.port);
    const std::string request =
        "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority +
        "\r\nConnection: close\r\n\r\n";
    std::size_t sent = 0;
    while (sent < request.size()) {
        const int count = send(
            *connection, request.data() + sent,
            static_cast<int>(request.size() - sent), 0);
        if (count == SOCKET_ERROR) {
            const int code = WSAGetLastError();
            return std::unexpected(error(
                ExitCode::proxy, static_cast<std::uint32_t>(code),
                L"Send proxy CONNECT probe"));
        }
        sent += static_cast<std::size_t>(count);
    }
    std::array<char, 512> response{};
    const int received =
        recv(*connection, response.data(), static_cast<int>(response.size() - 1), 0);
    if (received <= 0) {
        const int code = received == SOCKET_ERROR ? WSAGetLastError() : ERROR_BAD_NET_RESP;
        return std::unexpected(error(
            ExitCode::proxy, static_cast<std::uint32_t>(code),
            L"Read proxy CONNECT response"));
    }
    const std::string_view status(response.data(), static_cast<std::size_t>(received));
    const std::size_t space = status.find(' ');
    if (!status.starts_with("HTTP/1.") || space == std::string_view::npos ||
        space + 3 >= status.size() || status[space + 1] != '2') {
        return std::unexpected(error(
            ExitCode::proxy, ERROR_ACCESS_DENIED,
            L"Approved proxy CONNECT probe was rejected"));
    }
    return {};
}

enum class FilterKind { permit_v4, permit_v6, permit_v6_mapped, block };

Result<void> add_filter(
    HANDLE engine, const GUID& key, const wchar_t* name, const GUID& layer,
    FilterKind kind, std::uint16_t proxy_port, FWP_BYTE_BLOB& user_descriptor,
    PSECURITY_DESCRIPTOR object_descriptor) {
    std::array<FWPM_FILTER_CONDITION0, 4> conditions{};
    conditions[0].fieldKey = FWPM_CONDITION_ALE_USER_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
    conditions[0].conditionValue.sd = &user_descriptor;
    UINT32 count = 1;

    FWP_BYTE_ARRAY16 address_v6{};
    if (kind != FilterKind::block) {
        conditions[count].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        conditions[count].matchType = FWP_MATCH_EQUAL;
        conditions[count].conditionValue.type = FWP_UINT8;
        conditions[count].conditionValue.uint8 = IPPROTO_TCP;
        ++count;

        conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[count].matchType = FWP_MATCH_EQUAL;
        if (kind == FilterKind::permit_v4) {
            conditions[count].conditionValue.type = FWP_UINT32;
            conditions[count].conditionValue.uint32 = 0x7F000001U;
        } else {
            conditions[count].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
            if (kind == FilterKind::permit_v6) {
                address_v6.byteArray16[15] = 1;
            } else {
                address_v6.byteArray16[10] = 0xff;
                address_v6.byteArray16[11] = 0xff;
                address_v6.byteArray16[12] = 127;
                address_v6.byteArray16[15] = 1;
            }
            conditions[count].conditionValue.byteArray16 = &address_v6;
        }
        ++count;

        conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[count].matchType = FWP_MATCH_EQUAL;
        conditions[count].conditionValue.type = FWP_UINT16;
        conditions[count].conditionValue.uint16 = proxy_port;
        ++count;
    }

    std::uint64_t weight =
        kind == FilterKind::block ? block_weight : permit_weight;
    FWPM_FILTER0 filter{};
    filter.filterKey = key;
    filter.displayData.name = const_cast<wchar_t*>(name);
    filter.displayData.description =
        const_cast<wchar_t*>(L"Per-user sandbox network policy");
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.providerKey = const_cast<GUID*>(&provider_key);
    filter.layerKey = layer;
    filter.subLayerKey = sublayer_key;
    filter.weight.type = FWP_UINT64;
    filter.weight.uint64 = &weight;
    filter.numFilterConditions = count;
    filter.filterCondition = conditions.data();
    filter.action.type =
        kind == FilterKind::block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;

    const DWORD code =
        FwpmFilterAdd0(engine, &filter, object_descriptor, nullptr);
    if (code != ERROR_SUCCESS) {
        return std::unexpected(win32_error(
            ExitCode::wfp, code, std::wstring(L"Add WFP filter ") + name));
    }
    return {};
}

Result<void> delete_policy_objects(HANDLE engine) {
    for (const GUID* key :
         {&permit_v4_key, &permit_v6_key, &permit_v6_mapped_key, &block_v4_key,
          &block_v6_key}) {
        const DWORD code = FwpmFilterDeleteByKey0(engine, key);
        if (code != ERROR_SUCCESS && code != FWP_E_FILTER_NOT_FOUND) {
            return std::unexpected(win32_error(
                ExitCode::wfp, code, L"Delete existing WFP filter"));
        }
    }
    DWORD code = FwpmSubLayerDeleteByKey0(engine, &sublayer_key);
    if (code != ERROR_SUCCESS && code != FWP_E_SUBLAYER_NOT_FOUND) {
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Delete existing WFP sublayer"));
    }
    code = FwpmProviderDeleteByKey0(engine, &provider_key);
    if (code != ERROR_SUCCESS && code != FWP_E_PROVIDER_NOT_FOUND) {
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Delete existing WFP provider"));
    }
    return {};
}

Result<void> write_wfp_policy(
    const Config& config, PSID sid, bool replace_existing) {
    auto engine = open_engine();
    if (!engine) {
        return std::unexpected(engine.error());
    }
    if (!replace_existing) {
        FWPM_PROVIDER0* existing{};
        const DWORD code =
            FwpmProviderGetByKey0(engine->value, &provider_key, &existing);
        if (code == ERROR_SUCCESS) {
            FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
            return std::unexpected(error(
                ExitCode::usage_or_config, ERROR_ALREADY_EXISTS,
                L"WFP policy is already installed; use repair"));
        }
        if (code != FWP_E_PROVIDER_NOT_FOUND) {
            return std::unexpected(win32_error(
                ExitCode::wfp, code, L"Check existing WFP provider"));
        }
    }

    DWORD code = FwpmTransactionBegin0(engine->value, 0);
    if (code != ERROR_SUCCESS) {
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Begin WFP policy transaction"));
    }
    bool transaction_active = true;
    auto abort = [&] {
        if (transaction_active) {
            FwpmTransactionAbort0(engine->value);
            transaction_active = false;
        }
    };

    if (replace_existing) {
        auto deleted = delete_policy_objects(engine->value);
        if (!deleted) {
            abort();
            return std::unexpected(deleted.error());
        }
    }

    auto object_sd = wfp_object_descriptor();
    auto user_sd = user_condition_descriptor(sid);
    if (!object_sd || !user_sd) {
        abort();
        return std::unexpected((!object_sd ? object_sd.error() : user_sd.error()));
    }

    FWPM_PROVIDER0 provider{};
    provider.providerKey = provider_key;
    provider.displayData.name = const_cast<wchar_t*>(L"Sandbox Network Provider");
    provider.displayData.description =
        const_cast<wchar_t*>(L"Persistent per-user default-deny network policy");
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    provider.providerData.size = sizeof(config.policy_version);
    provider.providerData.data = reinterpret_cast<UINT8*>(
        const_cast<std::uint32_t*>(&config.policy_version));
    code = FwpmProviderAdd0(
        engine->value, &provider,
        static_cast<PSECURITY_DESCRIPTOR>(object_sd->data()));
    if (code != ERROR_SUCCESS) {
        abort();
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Add WFP provider"));
    }

    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = sublayer_key;
    sublayer.displayData.name = const_cast<wchar_t*>(L"Sandbox Network Sublayer");
    sublayer.displayData.description =
        const_cast<wchar_t*>(L"Per-user proxy permit and default deny");
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.providerKey = const_cast<GUID*>(&provider_key);
    sublayer.weight = sublayer_weight;
    code = FwpmSubLayerAdd0(
        engine->value, &sublayer,
        static_cast<PSECURITY_DESCRIPTOR>(object_sd->data()));
    if (code != ERROR_SUCCESS) {
        abort();
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Add WFP sublayer"));
    }

    FWP_BYTE_BLOB user_blob{
        static_cast<UINT32>(user_sd->size()),
        reinterpret_cast<UINT8*>(user_sd->data())};
    const auto add = [&](const GUID& key, const wchar_t* name, const GUID& layer,
                         FilterKind kind) -> Result<void> {
        return add_filter(
            engine->value, key, name, layer, kind, config.proxy_port, user_blob,
            static_cast<PSECURITY_DESCRIPTOR>(object_sd->data()));
    };
    for (const auto& operation : std::array{
             std::tuple{&permit_v4_key, L"Sandbox proxy permit IPv4",
                        &FWPM_LAYER_ALE_AUTH_CONNECT_V4, FilterKind::permit_v4},
             std::tuple{&permit_v6_key, L"Sandbox proxy permit IPv6",
                        &FWPM_LAYER_ALE_AUTH_CONNECT_V6, FilterKind::permit_v6},
             std::tuple{&permit_v6_mapped_key,
                        L"Sandbox proxy permit IPv4-mapped IPv6",
                        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        FilterKind::permit_v6_mapped},
             std::tuple{&block_v4_key, L"Sandbox default deny IPv4",
                        &FWPM_LAYER_ALE_AUTH_CONNECT_V4, FilterKind::block},
             std::tuple{&block_v6_key, L"Sandbox default deny IPv6",
                        &FWPM_LAYER_ALE_AUTH_CONNECT_V6, FilterKind::block},
         }) {
        auto result = add(
            *std::get<0>(operation), std::get<1>(operation),
            *std::get<2>(operation), std::get<3>(operation));
        if (!result) {
            abort();
            return std::unexpected(result.error());
        }
    }

    code = FwpmTransactionCommit0(engine->value);
    if (code != ERROR_SUCCESS) {
        abort();
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Commit WFP policy transaction"));
    }
    transaction_active = false;
    return {};
}

const FWPM_FILTER_CONDITION0* find_condition(
    const FWPM_FILTER0& filter, const GUID& field) {
    for (UINT32 index = 0; index < filter.numFilterConditions; ++index) {
        if (IsEqualGUID(filter.filterCondition[index].fieldKey, field)) {
            return &filter.filterCondition[index];
        }
    }
    return nullptr;
}

Result<void> verify_filter(
    HANDLE engine, const GUID& key, const GUID& layer, FilterKind kind,
    std::uint16_t proxy_port, const std::vector<std::byte>& expected_user_sd) {
    FWPM_FILTER0* raw{};
    const DWORD code = FwpmFilterGetByKey0(engine, &key, &raw);
    if (code != ERROR_SUCCESS) {
        return std::unexpected(win32_error(
            ExitCode::verification, code, L"Read expected WFP filter"));
    }
    const auto release = [&] { FwpmFreeMemory0(reinterpret_cast<void**>(&raw)); };

    const std::uint64_t expected_weight =
        kind == FilterKind::block ? block_weight : permit_weight;
    const FWP_ACTION_TYPE expected_action =
        kind == FilterKind::block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    if (!IsEqualGUID(raw->layerKey, layer) ||
        !IsEqualGUID(raw->subLayerKey, sublayer_key) || !raw->providerKey ||
        !IsEqualGUID(*raw->providerKey, provider_key) ||
        raw->flags != FWPM_FILTER_FLAG_PERSISTENT ||
        raw->action.type != expected_action || raw->weight.type != FWP_UINT64 ||
        !raw->weight.uint64 || *raw->weight.uint64 != expected_weight ||
        raw->numFilterConditions != (kind == FilterKind::block ? 1U : 4U)) {
        release();
        return std::unexpected(error(
            ExitCode::verification, ERROR_INVALID_DATA,
            L"WFP filter metadata does not match the installed policy"));
    }

    const auto* user = find_condition(*raw, FWPM_CONDITION_ALE_USER_ID);
    if (!user || user->matchType != FWP_MATCH_EQUAL ||
        user->conditionValue.type != FWP_SECURITY_DESCRIPTOR_TYPE ||
        !user->conditionValue.sd ||
        user->conditionValue.sd->size != expected_user_sd.size() ||
        std::memcmp(
            user->conditionValue.sd->data, expected_user_sd.data(),
            expected_user_sd.size()) != 0) {
        release();
        return std::unexpected(error(
            ExitCode::verification, ERROR_INVALID_SID,
            L"WFP filter user condition does not match the configured account"));
    }

    if (kind != FilterKind::block) {
        const auto* protocol = find_condition(*raw, FWPM_CONDITION_IP_PROTOCOL);
        const auto* address =
            find_condition(*raw, FWPM_CONDITION_IP_REMOTE_ADDRESS);
        const auto* port = find_condition(*raw, FWPM_CONDITION_IP_REMOTE_PORT);
        if (!protocol || protocol->matchType != FWP_MATCH_EQUAL ||
            protocol->conditionValue.type != FWP_UINT8 ||
            protocol->conditionValue.uint8 != IPPROTO_TCP || !port ||
            port->matchType != FWP_MATCH_EQUAL ||
            port->conditionValue.type != FWP_UINT16 ||
            port->conditionValue.uint16 != proxy_port || !address ||
            address->matchType != FWP_MATCH_EQUAL) {
            release();
            return std::unexpected(error(
                ExitCode::verification, ERROR_INVALID_DATA,
                L"WFP proxy permit conditions do not match the policy"));
        }

        bool address_matches = false;
        if (kind == FilterKind::permit_v4) {
            address_matches =
                address->conditionValue.type == FWP_UINT32 &&
                address->conditionValue.uint32 == 0x7F000001U;
        } else if (
            address->conditionValue.type == FWP_BYTE_ARRAY16_TYPE &&
            address->conditionValue.byteArray16) {
            std::array<UINT8, 16> expected{};
            if (kind == FilterKind::permit_v6) {
                expected[15] = 1;
            } else {
                expected[10] = 0xff;
                expected[11] = 0xff;
                expected[12] = 127;
                expected[15] = 1;
            }
            address_matches =
                std::memcmp(
                    address->conditionValue.byteArray16->byteArray16,
                    expected.data(), expected.size()) == 0;
        }
        if (!address_matches) {
            release();
            return std::unexpected(error(
                ExitCode::verification, ERROR_INVALID_ADDRESS,
                L"WFP proxy permit address does not match the policy"));
        }
    }
    release();
    return {};
}

Result<void> verify_wfp_policy(const Config& config, PSID sid) {
    auto engine = open_engine(ExitCode::verification);
    if (!engine) {
        return std::unexpected(engine.error());
    }
    auto expected_user_sd = user_condition_descriptor(sid);
    if (!expected_user_sd) {
        return std::unexpected(expected_user_sd.error());
    }

    FWPM_PROVIDER0* provider{};
    DWORD code =
        FwpmProviderGetByKey0(engine->value, &provider_key, &provider);
    if (code != ERROR_SUCCESS) {
        return std::unexpected(win32_error(
            ExitCode::verification, code, L"Read expected WFP provider"));
    }
    const bool provider_matches =
        provider->flags == FWPM_PROVIDER_FLAG_PERSISTENT &&
        provider->serviceName == nullptr &&
        provider->providerData.size == sizeof(config.policy_version) &&
        provider->providerData.data &&
        std::memcmp(
            provider->providerData.data, &config.policy_version,
            sizeof(config.policy_version)) == 0;
    FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
    if (!provider_matches) {
        return std::unexpected(error(
            ExitCode::verification, ERROR_INVALID_DATA,
            L"WFP provider does not match the policy version"));
    }

    FWPM_SUBLAYER0* sublayer{};
    code = FwpmSubLayerGetByKey0(engine->value, &sublayer_key, &sublayer);
    if (code != ERROR_SUCCESS) {
        return std::unexpected(win32_error(
            ExitCode::verification, code, L"Read expected WFP sublayer"));
    }
    const bool sublayer_provider_matches =
        sublayer->providerKey &&
        IsEqualGUID(*sublayer->providerKey, provider_key);
    const bool sublayer_matches =
        sublayer->flags == FWPM_SUBLAYER_FLAG_PERSISTENT &&
        sublayer_provider_matches;
    const std::wstring sublayer_details =
        L" (flags=" + std::to_wstring(sublayer->flags) +
        L", weight=" + std::to_wstring(sublayer->weight) +
        L", provider=" +
        (sublayer_provider_matches ? L"expected" : L"different") + L")";
    FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));
    if (!sublayer_matches) {
        return std::unexpected(error(
            ExitCode::verification, ERROR_INVALID_DATA,
            L"WFP sublayer does not match the installed policy" +
                sublayer_details));
    }

    for (const auto& expected : std::array{
             std::tuple{&permit_v4_key, &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        FilterKind::permit_v4},
             std::tuple{&permit_v6_key, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        FilterKind::permit_v6},
             std::tuple{&permit_v6_mapped_key, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        FilterKind::permit_v6_mapped},
             std::tuple{&block_v4_key, &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        FilterKind::block},
             std::tuple{&block_v6_key, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        FilterKind::block},
         }) {
        auto verified = verify_filter(
            engine->value, *std::get<0>(expected), *std::get<1>(expected),
            std::get<2>(expected), config.proxy_port, *expected_user_sd);
        if (!verified) {
            return std::unexpected(verified.error());
        }
    }
    return {};
}

Result<void> remove_wfp_policy() {
    auto engine = open_engine();
    if (!engine) {
        return std::unexpected(engine.error());
    }
    DWORD code = FwpmTransactionBegin0(engine->value, 0);
    if (code != ERROR_SUCCESS) {
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Begin WFP removal transaction"));
    }
    auto removed = delete_policy_objects(engine->value);
    if (!removed) {
        FwpmTransactionAbort0(engine->value);
        return std::unexpected(removed.error());
    }
    code = FwpmTransactionCommit0(engine->value);
    if (code != ERROR_SUCCESS) {
        FwpmTransactionAbort0(engine->value);
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Commit WFP removal transaction"));
    }
    FWPM_PROVIDER0* provider{};
    code = FwpmProviderGetByKey0(engine->value, &provider_key, &provider);
    if (code == ERROR_SUCCESS) {
        FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
        return std::unexpected(error(
            ExitCode::wfp, ERROR_INVALID_DATA,
            L"WFP provider still exists after removal"));
    }
    if (code != FWP_E_PROVIDER_NOT_FOUND) {
        return std::unexpected(win32_error(
            ExitCode::wfp, code, L"Verify WFP policy removal"));
    }
    return {};
}

Result<std::vector<std::byte>> current_user_sid() {
    HANDLE raw_token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::precondition, code, L"Open current process token"));
    }
    UniqueHandle token(raw_token);
    DWORD size{};
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    DWORD code = GetLastError();
    if (code != ERROR_INSUFFICIENT_BUFFER) {
        return std::unexpected(win32_error(
            ExitCode::precondition, code, L"Size current user SID"));
    }
    std::vector<std::byte> data(size);
    if (!GetTokenInformation(
            token.get(), TokenUser, data.data(), size, &size)) {
        code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::precondition, code, L"Read current user SID"));
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(data.data());
    const DWORD sid_size = GetLengthSid(user->User.Sid);
    std::vector<std::byte> sid(sid_size);
    if (!CopySid(sid_size, sid.data(), user->User.Sid)) {
        code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::precondition, code, L"Copy current user SID"));
    }
    return sid;
}

Result<std::vector<std::byte>> well_known_sid(
    WELL_KNOWN_SID_TYPE type) {
    std::vector<std::byte> sid(SECURITY_MAX_SID_SIZE);
    DWORD size = static_cast<DWORD>(sid.size());
    if (!CreateWellKnownSid(type, nullptr, sid.data(), &size)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::verification, code, L"Create well-known SID"));
    }
    sid.resize(size);
    return sid;
}

Result<void> verify_protected_path(
    const std::filesystem::path& path, PSID sandbox_sid) {
    PSID owner{};
    PACL dacl{};
    PSECURITY_DESCRIPTOR raw{};
    const DWORD code = GetNamedSecurityInfoW(
        const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr,
        &dacl, nullptr, &raw);
    if (code != ERROR_SUCCESS) {
        return std::unexpected(win32_error(
            ExitCode::verification, code, L"Read filesystem protection"));
    }
    LocalMemory descriptor(raw, LocalFree);

    auto administrators = well_known_sid(WinBuiltinAdministratorsSid);
    auto system = well_known_sid(WinLocalSystemSid);
    auto everyone = well_known_sid(WinWorldSid);
    auto authenticated_users = well_known_sid(WinAuthenticatedUserSid);
    auto users = well_known_sid(WinBuiltinUsersSid);
    if (!administrators || !system || !everyone || !authenticated_users ||
        !users) {
        return std::unexpected(
            !administrators ? administrators.error()
            : !system       ? system.error()
            : !everyone     ? everyone.error()
            : !authenticated_users ? authenticated_users.error()
                                   : users.error());
    }
    if (!owner ||
        (!EqualSid(owner, administrators->data()) &&
         !EqualSid(owner, system->data()))) {
        return std::unexpected(error(
            ExitCode::verification, ERROR_INVALID_OWNER,
            L"Protected path is not owned by Administrators or SYSTEM: " +
                path.wstring()));
    }
    if (!dacl) {
        return std::unexpected(error(
            ExitCode::verification, ERROR_ACCESS_DENIED,
            L"Protected path has an unrestricted DACL: " + path.wstring()));
    }

    constexpr ACCESS_MASK write_access =
        GENERIC_ALL | GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA |
        FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE |
        WRITE_DAC | WRITE_OWNER;
    ACL_SIZE_INFORMATION information{};
    if (!GetAclInformation(
            dacl, &information, sizeof(information), AclSizeInformation)) {
        const DWORD acl_code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::verification, acl_code, L"Read filesystem ACL"));
    }
    for (DWORD index = 0; index < information.AceCount; ++index) {
        void* raw_ace{};
        if (!GetAce(dacl, index, &raw_ace)) {
            const DWORD ace_code = GetLastError();
            return std::unexpected(win32_error(
                ExitCode::verification, ace_code, L"Read filesystem ACE"));
        }
        const auto* header = static_cast<const ACE_HEADER*>(raw_ace);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            continue;
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
        PSID trustee = const_cast<DWORD*>(&ace->SidStart);
        const bool untrusted =
            EqualSid(trustee, sandbox_sid) ||
            EqualSid(trustee, everyone->data()) ||
            EqualSid(trustee, authenticated_users->data()) ||
            EqualSid(trustee, users->data());
        if (untrusted && (ace->Mask & write_access) != 0) {
            return std::unexpected(error(
                ExitCode::verification, ERROR_ACCESS_DENIED,
                L"Sandbox or ordinary users can modify protected path: " +
                    path.wstring()));
        }
    }
    return {};
}

Result<void> verify_runtime_paths(const Config& config, PSID sandbox_sid) {
    for (const auto& protected_path :
         {installed_policy_path().parent_path(), installed_policy_path(),
          config.proxy_adapter.parent_path(), config.proxy_adapter}) {
        auto protection = verify_protected_path(protected_path, sandbox_sid);
        if (!protection) {
            return std::unexpected(protection.error());
        }
    }
    return {};
}

Result<void> expect_loopback_blocked(int family, int type, int protocol) {
    auto listener = make_socket(family, type, protocol);
    if (*listener == INVALID_SOCKET) {
        return std::unexpected(error(
            ExitCode::verification, static_cast<std::uint32_t>(WSAGetLastError()),
            L"Create loopback test listener"));
    }

    sockaddr_storage address{};
    int address_size{};
    if (family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&address);
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address_size = sizeof(*v4);
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&address);
        v6->sin6_family = AF_INET6;
        v6->sin6_addr = in6addr_loopback;
        address_size = sizeof(*v6);
        DWORD only_v6 = 1;
        setsockopt(
            *listener, IPPROTO_IPV6, IPV6_V6ONLY,
            reinterpret_cast<const char*>(&only_v6), sizeof(only_v6));
    }
    if (bind(
            *listener, reinterpret_cast<const sockaddr*>(&address),
            address_size) == SOCKET_ERROR) {
        return std::unexpected(error(
            ExitCode::verification, static_cast<std::uint32_t>(WSAGetLastError()),
            L"Bind loopback test listener"));
    }
    if (type == SOCK_STREAM && listen(*listener, 1) == SOCKET_ERROR) {
        return std::unexpected(error(
            ExitCode::verification, static_cast<std::uint32_t>(WSAGetLastError()),
            L"Listen for loopback test"));
    }
    if (getsockname(
            *listener, reinterpret_cast<sockaddr*>(&address),
            &address_size) == SOCKET_ERROR) {
        return std::unexpected(error(
            ExitCode::verification, static_cast<std::uint32_t>(WSAGetLastError()),
            L"Read loopback test port"));
    }

    auto client = make_socket(family, type, protocol);
    if (*client == INVALID_SOCKET) {
        return std::unexpected(error(
            ExitCode::verification, static_cast<std::uint32_t>(WSAGetLastError()),
            L"Create loopback test client"));
    }
    if (connect(
            *client, reinterpret_cast<const sockaddr*>(&address),
            address_size) == SOCKET_ERROR) {
        const int code = WSAGetLastError();
        if (code == WSAEACCES) {
            return {};
        }
        return std::unexpected(error(
            ExitCode::verification, static_cast<std::uint32_t>(code),
            L"Loopback test failed for a reason other than WFP denial"));
    }
    if (type == SOCK_DGRAM) {
        const char value = 0;
        if (send(*client, &value, 1, 0) == SOCKET_ERROR &&
            WSAGetLastError() == WSAEACCES) {
            return {};
        }
    }
    return std::unexpected(error(
        ExitCode::verification, ERROR_ACCESS_DENIED,
        L"Direct non-proxy loopback connection was not blocked"));
}

Result<std::filesystem::path> current_executable() {
    std::wstring path(260, L'\0');
    for (;;) {
        const DWORD length =
            GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (!length) {
            const DWORD code = GetLastError();
            return std::unexpected(win32_error(
                ExitCode::verification, code, L"Locate test executable"));
        }
        if (length < path.size() - 1) {
            path.resize(length);
            return std::filesystem::path(std::move(path));
        }
        path.resize(path.size() * 2);
    }
}

Result<void> run_child_enforcement_test() {
    auto executable = current_executable();
    if (!executable) {
        return std::unexpected(executable.error());
    }
    if (!SetEnvironmentVariableW(L"SANDBOX_NETWORK_TEST_CHILD", L"1")) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::verification, code, L"Prepare child enforcement test"));
    }
    std::wstring command_line =
        quote_argument(executable->wstring()) + L" test";
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(
        executable->c_str(), command_line.data(), nullptr, nullptr, FALSE, 0,
        nullptr, executable->parent_path().c_str(), &startup, &process);
    const DWORD creation_code = created ? ERROR_SUCCESS : GetLastError();
    SetEnvironmentVariableW(L"SANDBOX_NETWORK_TEST_CHILD", nullptr);
    if (!created) {
        return std::unexpected(win32_error(
            ExitCode::verification, creation_code,
            L"Start child enforcement test"));
    }
    UniqueHandle process_handle(process.hProcess);
    UniqueHandle thread_handle(process.hThread);
    const DWORD wait = WaitForSingleObject(process_handle.get(), 30'000);
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(process_handle.get(), ERROR_TIMEOUT);
        WaitForSingleObject(process_handle.get(), 5'000);
        return std::unexpected(error(
            ExitCode::verification, ERROR_TIMEOUT,
            L"Child enforcement test timed out"));
    }
    if (wait != WAIT_OBJECT_0) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::verification, code, L"Wait for child enforcement test"));
    }
    DWORD exit_code{};
    if (!GetExitCodeProcess(process_handle.get(), &exit_code)) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::verification, code,
            L"Read child enforcement test result"));
    }
    if (exit_code != 0) {
        return std::unexpected(error(
            ExitCode::verification, exit_code,
            L"Child process bypass test failed"));
    }
    return {};
}

Result<void> verify_installed() {
    auto config = load_config(installed_policy_path());
    if (!config) {
        return std::unexpected(config.error());
    }
    auto adapter_valid = validate_adapter_path(config->proxy_adapter);
    if (!adapter_valid) {
        return std::unexpected(adapter_valid.error());
    }
    auto sid = resolve_account_sid(config->account);
    if (!sid) {
        return std::unexpected(sid.error());
    }
    auto paths = verify_runtime_paths(*config, sid->data());
    if (!paths) {
        return std::unexpected(paths.error());
    }
    auto wfp = verify_wfp_policy(*config, sid->data());
    if (!wfp) {
        return std::unexpected(wfp.error());
    }
    auto adapter = run_adapter(*config, L"verify");
    if (!adapter) {
        return std::unexpected(adapter.error());
    }
    auto listeners = verify_proxy_listeners(config->proxy_port);
    if (!listeners) {
        return std::unexpected(listeners.error());
    }
    return verify_approved_connect(*config);
}

Result<void> install_command(const std::filesystem::path& source) {
    auto elevated = require_elevation();
    if (!elevated) {
        return std::unexpected(elevated.error());
    }
    auto config = install_config_file(source, false);
    if (!config) {
        return std::unexpected(config.error());
    }
    auto sid = resolve_account_sid(config->account);
    if (!sid) {
        return std::unexpected(sid.error());
    }
    auto paths = verify_runtime_paths(*config, sid->data());
    if (!paths) {
        return std::unexpected(paths.error());
    }
    auto adapter = run_adapter(*config, L"apply");
    if (!adapter) {
        return std::unexpected(adapter.error());
    }
    adapter = run_adapter(*config, L"verify");
    if (!adapter) {
        return std::unexpected(adapter.error());
    }
    auto listeners = verify_proxy_listeners(config->proxy_port);
    if (!listeners) {
        return std::unexpected(listeners.error());
    }
    auto probe = verify_approved_connect(*config);
    if (!probe) {
        return std::unexpected(probe.error());
    }
    auto written = write_wfp_policy(*config, sid->data(), false);
    if (!written) {
        return std::unexpected(written.error());
    }
    return verify_installed();
}

Result<void> repair_command(
    const std::optional<std::filesystem::path>& source) {
    auto elevated = require_elevation();
    if (!elevated) {
        return std::unexpected(elevated.error());
    }
    Result<Config> config = source
                                ? install_config_file(*source, true)
                                : load_config(installed_policy_path());
    if (!config) {
        return std::unexpected(config.error());
    }
    auto adapter_valid = validate_adapter_path(config->proxy_adapter);
    if (!adapter_valid) {
        return std::unexpected(adapter_valid.error());
    }
    auto protected_adapter = protect_managed_adapter(config->proxy_adapter);
    if (!protected_adapter) {
        return std::unexpected(protected_adapter.error());
    }
    auto sid = resolve_account_sid(config->account);
    if (!sid) {
        return std::unexpected(sid.error());
    }
    auto paths = verify_runtime_paths(*config, sid->data());
    if (!paths) {
        return std::unexpected(paths.error());
    }
    auto adapter = run_adapter(*config, L"apply");
    if (!adapter) {
        return std::unexpected(adapter.error());
    }
    adapter = run_adapter(*config, L"verify");
    if (!adapter) {
        return std::unexpected(adapter.error());
    }
    auto listeners = verify_proxy_listeners(config->proxy_port);
    if (!listeners) {
        return std::unexpected(listeners.error());
    }
    auto probe = verify_approved_connect(*config);
    if (!probe) {
        return std::unexpected(probe.error());
    }
    auto written = write_wfp_policy(*config, sid->data(), true);
    if (!written) {
        return std::unexpected(written.error());
    }
    return verify_installed();
}

Result<void> remove_command() {
    auto elevated = require_elevation();
    if (!elevated) {
        return std::unexpected(elevated.error());
    }
    auto config = load_config(installed_policy_path());
    if (!config) {
        return std::unexpected(config.error());
    }
    auto sid = resolve_account_sid(config->account);
    if (!sid) {
        return std::unexpected(sid.error());
    }
    auto paths = verify_runtime_paths(*config, sid->data());
    if (!paths) {
        return std::unexpected(paths.error());
    }
    auto adapter = run_adapter(*config, L"remove");
    if (!adapter) {
        return std::unexpected(adapter.error());
    }
    auto removed = remove_wfp_policy();
    if (!removed) {
        return std::unexpected(removed.error());
    }
    if (!DeleteFileW(installed_policy_path().c_str())) {
        const DWORD code = GetLastError();
        return std::unexpected(win32_error(
            ExitCode::precondition, code, L"Delete installed policy"));
    }
    return {};
}

Result<void> test_command() {
    auto config = load_config(installed_policy_path());
    if (!config) {
        return std::unexpected(config.error());
    }
    auto expected_sid = resolve_account_sid(config->account);
    if (!expected_sid) {
        return std::unexpected(expected_sid.error());
    }
    auto caller_sid = current_user_sid();
    if (!caller_sid) {
        return std::unexpected(caller_sid.error());
    }
    if (!EqualSid(caller_sid->data(), expected_sid->data())) {
        return std::unexpected(error(
            ExitCode::precondition, ERROR_INVALID_OWNER,
            L"test must run as the configured sandbox account"));
    }
    auto verified = verify_installed();
    if (!verified) {
        return std::unexpected(verified.error());
    }

    Winsock winsock;
    if (!winsock.active) {
        return std::unexpected(error(
            ExitCode::verification,
            static_cast<std::uint32_t>(WSAGetLastError()),
            L"Initialize Winsock"));
    }
    for (const auto [family, type, protocol] :
         {std::tuple{AF_INET, SOCK_STREAM, IPPROTO_TCP},
          std::tuple{AF_INET6, SOCK_STREAM, IPPROTO_TCP},
          std::tuple{AF_INET, SOCK_DGRAM, IPPROTO_UDP},
          std::tuple{AF_INET6, SOCK_DGRAM, IPPROTO_UDP}}) {
        auto blocked = expect_loopback_blocked(family, type, protocol);
        if (!blocked) {
            return std::unexpected(blocked.error());
        }
    }
    if (GetEnvironmentVariableW(
            L"SANDBOX_NETWORK_TEST_CHILD", nullptr, 0) == 0) {
        return run_child_enforcement_test();
    }
    return {};
}

void print_usage() {
    std::wcerr
        << L"Usage:\n"
        << L"  sandbox-network install --config <path>\n"
        << L"  sandbox-network verify\n"
        << L"  sandbox-network repair [--config <path>]\n"
        << L"  sandbox-network remove\n"
        << L"  sandbox-network test\n";
}

void write_event(WORD type, std::wstring_view message) {
    HANDLE source = RegisterEventSourceW(nullptr, L"SandboxNetwork");
    if (!source) {
        return;
    }
    std::wstring owned(message);
    const wchar_t* strings[] = {owned.c_str()};
    ReportEventW(
        source, type, 0, 1, nullptr, 1, 0, strings, nullptr);
    DeregisterEventSource(source);
}

int finish(Result<void> result, std::wstring_view success_message) {
    if (!result) {
        std::wcerr << L"Error: " << result.error().message << L'\n';
        write_event(EVENTLOG_ERROR_TYPE, result.error().message);
        return static_cast<int>(result.error().exit_code);
    }
    std::wcout << success_message << L'\n';
    write_event(EVENTLOG_INFORMATION_TYPE, success_message);
    return static_cast<int>(ExitCode::success);
}

} // namespace

int run(std::span<const std::wstring_view> arguments) {
    if (arguments.empty()) {
        print_usage();
        return static_cast<int>(ExitCode::usage_or_config);
    }
    const auto command = arguments.front();
    if (command == L"install") {
        if (arguments.size() != 3 || arguments[1] != L"--config") {
            print_usage();
            return static_cast<int>(ExitCode::usage_or_config);
        }
        return finish(
            install_command(std::filesystem::path(arguments[2])),
            L"Sandbox network policy installed and verified.");
    }
    if (command == L"verify") {
        if (arguments.size() != 1) {
            print_usage();
            return static_cast<int>(ExitCode::usage_or_config);
        }
        return finish(
            verify_installed(), L"Sandbox network policy is active.");
    }
    if (command == L"repair") {
        if (arguments.size() == 1) {
            return finish(
                repair_command(std::nullopt),
                L"Sandbox network policy repaired and verified.");
        }
        if (arguments.size() == 3 && arguments[1] == L"--config") {
            return finish(
                repair_command(std::filesystem::path(arguments[2])),
                L"Sandbox network policy repaired and verified.");
        }
        print_usage();
        return static_cast<int>(ExitCode::usage_or_config);
    }
    if (command == L"remove") {
        if (arguments.size() != 1) {
            print_usage();
            return static_cast<int>(ExitCode::usage_or_config);
        }
        return finish(
            remove_command(), L"Sandbox network policy removed.");
    }
    if (command == L"test") {
        if (arguments.size() != 1) {
            print_usage();
            return static_cast<int>(ExitCode::usage_or_config);
        }
        return finish(
            test_command(), L"Sandbox network enforcement tests passed.");
    }
    print_usage();
    return static_cast<int>(ExitCode::usage_or_config);
}

} // namespace sandbox_network
