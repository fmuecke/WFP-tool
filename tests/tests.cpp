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
proxy_adapter=C:\Program Files\SandboxProxyAdapter\adapter.exe
proxy_log=C:\ProgramData\SandboxNetwork\proxy.log

[allow]
API.ANTHROPIC.COM=443
auth.example.com=8443

[probe]
approved=api.anthropic.com:443
)ini";

void config_tests() {
    auto parsed = sandbox_network::parse_config(valid_config);
    check(parsed.has_value(), "valid configuration parses");
    if (parsed) {
        check(parsed->policy_version == 7, "policy version is parsed");
        check(parsed->proxy_port == 8080, "proxy port is parsed");
        check(parsed->allow.size() == 2, "allowlist is parsed");
        check(
            parsed->approved_probe ==
                sandbox_network::Endpoint{"api.anthropic.com", 443},
            "hostnames are normalized");
    }

    const auto replace = [](std::string text, std::string_view from,
                            std::string_view to) {
        text.replace(text.find(from), from.size(), to);
        return text;
    };
    check(
        !sandbox_network::parse_config(
             replace(std::string(valid_config), "API.ANTHROPIC.COM", "*.example.com"))
             .has_value(),
        "wildcard hostnames are rejected");
    check(
        !sandbox_network::parse_config(
             replace(std::string(valid_config), "API.ANTHROPIC.COM", "127.0.0.1"))
             .has_value(),
        "IP-literal destinations are rejected");
    check(
        !sandbox_network::parse_config(
             replace(std::string(valid_config), "API.ANTHROPIC.COM", "123.456"))
             .has_value(),
        "numeric hostnames are rejected");
    check(
        !sandbox_network::parse_config(
             replace(
                 std::string(valid_config), "API.ANTHROPIC.COM",
                 "api.anthropic.com."))
             .has_value(),
        "trailing-dot hostnames are rejected");
    check(
        !sandbox_network::parse_config(
             replace(std::string(valid_config), "proxy_port=8080", "proxy_port=0"))
             .has_value(),
        "port zero is rejected");
    check(
        !sandbox_network::parse_config(
             replace(
                 std::string(valid_config), "approved=api.anthropic.com:443",
                 "approved=denied.example.com:443"))
             .has_value(),
        "approved probe must be allowlisted");
    check(
        !sandbox_network::parse_config(
             replace(std::string(valid_config), "[probe]", "[unknown]"))
             .has_value(),
        "unknown sections are rejected");
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
