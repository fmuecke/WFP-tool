#include "sandbox_network.h"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

int failures = 0;

void check(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

constexpr std::string_view valid_config = R"ini(
[policy]
account=ClaudeSandbox
policy_version=7
proxy_port=8080

[wfp-allow]
203.0.113.10:1234=tcp,udp
[2001:db8::10]:443=udp

[allow]
api.anthropic.com=443
)ini";

void config_tests() {
    auto parsed = sandbox_network::parse_config(valid_config);
    check(parsed.has_value(), "valid configuration parses");
    if (parsed) {
        check(parsed->policy_version == 7, "policy version is parsed");
        check(parsed->allow.size() == 2, "two endpoints are parsed");
        if (parsed->allow.size() == 2) {
            check(!parsed->allow[0].ipv6 && parsed->allow[0].tcp && parsed->allow[0].udp,
                  "IPv4 TCP and UDP endpoint is parsed");
            check(parsed->allow[1].ipv6 && !parsed->allow[1].tcp && parsed->allow[1].udp,
                  "IPv6 UDP endpoint is parsed");
        }
    }

    const auto replace = [](std::string text, std::string_view from,
                            std::string_view to) {
        text.replace(text.find(from), from.size(), to);
        return text;
    };
    check(
        !sandbox_network::parse_config(
             replace(std::string(valid_config), "policy_version=7", "policy_version=0"))
             .has_value(),
        "policy version zero is rejected");
    check(
        !sandbox_network::parse_config(
             replace(
                 std::string(valid_config),
                 "203.0.113.10:1234=tcp,udp\n[2001:db8::10]:443=udp",
                 ""))
             .has_value(),
        "missing WFP allowlist is rejected");
    check(
        !sandbox_network::parse_config(
             replace(std::string(valid_config), "[2001:db8::10]:443=udp", "2001:db8::10:443=udp"))
             .has_value(),
        "unbracketed IPv6 is rejected");
    check(
        !sandbox_network::parse_config(
             replace(std::string(valid_config), "203.0.113.10:1234=tcp,udp", "203.0.113.10:1234=tcp,tcp"))
             .has_value(),
        "duplicate protocol is rejected");
    check(
        !sandbox_network::parse_config(
             replace(std::string(valid_config), "[2001:db8::10]:443=udp", "203.0.113.10:1234=udp"))
             .has_value(),
        "duplicate endpoint is rejected");
    check(
        sandbox_network::parse_config(
            replace(std::string(valid_config), "[allow]", "[gost-options]"))
            .has_value(),
        "non-WFP sections are ignored");
}

void cli_tests() {
    check(
        sandbox_network::run({}) ==
            static_cast<int>(sandbox_network::ExitCode::usage_or_config),
        "empty CLI is a usage error");
    constexpr std::wstring_view unknown[] = {L"unknown"};
    check(
        sandbox_network::run(unknown) ==
            static_cast<int>(sandbox_network::ExitCode::usage_or_config),
        "unknown command is a usage error");
    for (const auto command : {L"apply", L"verify", L"remove"}) {
        const std::wstring_view arguments[] = {command};
        check(
            sandbox_network::run(arguments) ==
                static_cast<int>(sandbox_network::ExitCode::usage_or_config),
            "configuration command requires a configuration");
    }
    constexpr std::wstring_view invalid_list[] = {L"list"};
    check(
        sandbox_network::run(invalid_list) ==
            static_cast<int>(sandbox_network::ExitCode::usage_or_config),
        "list requires a user");
    constexpr std::wstring_view invalid_clear[] = {L"clear"};
    check(
        sandbox_network::run(invalid_clear) ==
            static_cast<int>(sandbox_network::ExitCode::usage_or_config),
        "clear requires a user");
}

} // namespace

int main() {
    config_tests();
    cli_tests();
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "All tests passed\n";
    return EXIT_SUCCESS;
}
