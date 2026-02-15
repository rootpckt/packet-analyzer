message(STATUS "USING THIS CMAKE FILE")
cmake_minimum_required(VERSION 3.20)
project(packet_analyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(pcktAnalyzer
        pcktAnalyzer.cpp
)

find_library(PCAP_LIB pcap REQUIRED)
target_link_libraries(pcktAnalyzer PRIVATE ${PCAP_LIB})