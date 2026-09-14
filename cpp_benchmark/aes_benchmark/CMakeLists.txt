cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(aes_benchmark C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(aes_benchmark
    src/main.cpp
    src/aes.cpp
)

target_include_directories(aes_benchmark PRIVATE src)

target_link_libraries(aes_benchmark
    pico_stdlib
    hardware_timer
    hardware_adc
)

pico_add_extra_outputs(aes_benchmark)
pico_enable_stdio_usb(aes_benchmark 1)
pico_enable_stdio_uart(aes_benchmark 0)
