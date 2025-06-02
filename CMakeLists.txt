cmake_minimum_required(VERSION 3.10)
project(SimpleLeakDetector LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# 设置构建类型（可选）
set(CMAKE_BUILD_TYPE Debug)

# 添加调试符号（仅 Debug 模式下）
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_DEBUG "-g")

# 添加 C 模块为静态库（用 gcc 编译）
add_library(injector STATIC Injector.c)

# 添加 MallocHooker 模块
add_library(MallocHooker SHARED MallocHooker.cpp)
target_link_libraries(MallocHooker PRIVATE -static-libgcc -static-libstdc++)
# 指定输出文件名
set_target_properties(MallocHooker PROPERTIES
    OUTPUT_NAME "MallocHooker"
    PREFIX ""                             # 去掉前缀 "lib"
)

# 添加 HeapAllocHooker 模块
add_library(HeapAllocHooker SHARED HeapAllocHooker.cpp)
target_link_libraries(HeapAllocHooker PRIVATE -static-libgcc -static-libstdc++)
# 指定输出文件名
set_target_properties(HeapAllocHooker PROPERTIES
    OUTPUT_NAME "HeapAllocHooker"
    PREFIX ""                             # 去掉前缀 "lib"
)

# 添加 C++ 可执行文件（用 g++ 编译）
add_executable(LeakDetector LeakDetector.cpp)

# 链接 C 静态库
target_link_libraries(LeakDetector PRIVATE injector kernel32 user32 ntdll dbghelp -static-libgcc -static-libstdc++)