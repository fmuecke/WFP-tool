#pragma once

#include "sandbox_network.h"

#include <span>
#include <string_view>

namespace dummy_proxy {

bool request_allowed(
    std::string_view request,
    std::span<const sandbox_network::Endpoint> allowlist);
int run(std::span<const std::wstring_view> arguments);

} // namespace dummy_proxy
