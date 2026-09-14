// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/WFP-tool.git

#pragma once

#include <cstdint>
#include <span>
#include <string_view>

namespace wfp_tool {

enum class ExitCode : int {
  success = 0,
  usage = 2,
  precondition = 3,
  wfp = 4,
  verification = 6,
};

int run(std::span<const std::wstring_view> arguments);

} // namespace wfp_tool
