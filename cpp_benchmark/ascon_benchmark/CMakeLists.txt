cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(ascon_benchmark C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(ascon_benchmark
    src/main.cpp
    src/ascon.cpp
)

target_include_directories(ascon_benchmark PRIVATE src)

target_link_libraries(ascon_benchmark
    pico_stdlib
    hardware_timer
    hardware_adc
)

pico_add_extra_outputs(ascon_benchmark)
pico_enable_stdio_usb(ascon_benchmark 1)
pico_enable_stdio_uart(ascon_benchmark 0)
