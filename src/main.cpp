#include "sandbox_network.h"

#include <string_view>
#include <vector>

int wmain(int argc, wchar_t** argv) {
    std::vector<std::wstring_view> arguments;
    arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
    for (int index = 1; index < argc; ++index) {
        arguments.emplace_back(argv[index]);
    }
    return sandbox_network::run(arguments);
}
