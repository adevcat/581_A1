cmake_minimum_required(VERSION 3.20)
project(581_A1 CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(ipv4_analyzer ipv4_analyzer.cpp)

add_executable(581_A1 main.cpp)
target_link_libraries(581_A1 PRIVATE ipv4_analyzer)

add_executable(test_runner tests.cpp)
target_link_libraries(test_runner PRIVATE ipv4_analyzer)

enable_testing()
add_test(NAME IPv4Tests COMMAND test_runner)
