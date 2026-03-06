cmake_minimum_required(VERSION 3.10)
project(tun_alloc C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(tun_alloc main.c)

target_compile_options(tun_alloc PRIVATE -Wall -Wextra)