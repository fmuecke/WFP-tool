#pragma once

#include <array>
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
    proxy = 5, // Reserved for compatibility with earlier releases.
    verification = 6,
};

struct Error {
    ExitCode exit_code;
    std::uint32_t native_code;
    std::wstring message;
};

template <class T>
using Result = std::expected<T, Error>;

struct Config {
    std::wstring account;
    std::uint32_t policy_version;
    struct Endpoint {
        bool ipv6;
        std::array<std::uint8_t, 16> address;
        std::uint16_t port;
        bool tcp;
        bool udp;
    };
    std::vector<Endpoint> allow;
};

Result<Config> parse_config(std::string_view text);
Result<Config> load_config(const std::filesystem::path& path);
int run(std::span<const std::wstring_view> arguments);

} // namespace sandbox_network
