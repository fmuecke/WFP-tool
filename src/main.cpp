// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project : https: // github.com/fmuecke/WFP-tool.git

#include "wfp_tool.h"

#include <string_view>
#include <vector>

int wmain(int argc, wchar_t **argv) {
  std::vector<std::wstring_view> arguments;
  arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  return wfp_tool::run(arguments);
}
