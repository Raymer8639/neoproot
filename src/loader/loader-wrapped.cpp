#include <cstddef>
#include <cstdint>

extern "C" {
    // 注意：loader.inc 由 Makefile 自动生成
    // 如果你现在没有，先空着，编译时会自动生成
    const char _binary_loader_exe_start[] = {
        // 这里会被 xxd 生成的内容填充
    };

    const char _binary_loader_exe_end[] = {};
    const int offset_to_pokedata_workaround = 0;
}
