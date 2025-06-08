cmake_minimum_required(VERSION 3.10)
project(SimpleLeakDetector LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Configuring Debug build")
    add_compile_options(-g -O0 -DDEBUG)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Configuring Release build")
    add_compile_options(-O3 -DNDEBUG)
endif()

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
target_link_libraries(LeakDetector PRIVATE kernel32 user32 ntdll dbghelp -static-libgcc -static-libstdc++)