cmake_minimum_required(VERSION 3.10)

project(Shadow VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(include)

# add the executable libpcap.a
add_executable(Shadow main.cpp include/httplib.h)
target_link_libraries(Shadow PUBLIC pcap pthread)