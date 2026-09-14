// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project : https: // github.com/fmuecke/user-net-lock.git

#include "user_net_lock.h"

#include <string_view>
#include <vector>
//#include <cstdio>
#include <fcntl.h>
#include <io.h>
//#include <iostream>

int wmain(int argc, wchar_t** argv)
{
    static_cast<void>(_setmode(_fileno(stdout), _O_U8TEXT));
    static_cast<void>(_setmode(_fileno(stderr), _O_U8TEXT));

    std::vector<std::wstring_view> arguments;
    arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
    for (int index = 1; index < argc; ++index)
    {
        arguments.emplace_back(argv[index]);
    }
    return user_net_lock::run(arguments);
}
