cmake_minimum_required(VERSION 3.10)
project(tun_read)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(tun_read
#    tun_read.cpp
#tun_read2.cpp
    net_filter_queue.cpp
    tunnel.cpp
    inbound_traffic.cpp
    outbound_traffic.cpp
    temp/event_poller.cpp
    temp/logger.cpp
    main.cpp

)

target_include_directories(tun_read PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/temp")


target_link_libraries(tun_read PRIVATE netfilter_queue)
