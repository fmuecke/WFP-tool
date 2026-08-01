#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sandbox_network {

enum class ExitCode : int {
    success = 0,
    usage_or_config = 2,
    precondition = 3,
    wfp = 4,
    proxy = 5,
    verification = 6,
};

struct Error {
    ExitCode exit_code;
    std::uint32_t native_code;
    std::wstring message;
};

template <class T>
using Result = std::expected<T, Error>;

struct Endpoint {
    std::string hostname;
    std::uint16_t port;

    bool operator==(const Endpoint&) const = default;
};

struct Config {
    std::wstring account;
    std::uint32_t policy_version;
    std::uint16_t proxy_port;
    std::filesystem::path proxy_adapter;
    std::filesystem::path proxy_log;
    std::vector<Endpoint> allow;
    Endpoint approved_probe;
};

Result<Config> parse_config(std::string_view text);
Result<Config> load_config(const std::filesystem::path& path);
std::filesystem::path installed_policy_path();
int run(std::span<const std::wstring_view> arguments);

} // namespace sandbox_network
