cmake_minimum_required(VERSION 3.10)
project(tun_read)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(tun_read
    tun_read.cpp
    net_filter_queue.cpp
    tunnel.cpp
)

target_link_libraries(tun_read PRIVATE netfilter_queue)