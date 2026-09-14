cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(present_benchmark C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(present_benchmark
    src/main.cpp
    src/present.cpp
)

target_include_directories(present_benchmark PRIVATE src)

target_link_libraries(present_benchmark
    pico_stdlib
    hardware_timer
    hardware_adc
)

pico_add_extra_outputs(present_benchmark)
pico_enable_stdio_usb(present_benchmark 1)
pico_enable_stdio_uart(present_benchmark 0)
