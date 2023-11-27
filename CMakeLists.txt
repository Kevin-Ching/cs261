cmake_minimum_required(VERSION 3.13)

project(tests)

add_executable(tests simple_test.cpp my_utils.h)

add_subdirectory(SEAL)
target_link_libraries(tests PUBLIC seal)
target_include_directories(tests PUBLIC SEAL)
# target_link_directories(tests PRIVATE SEAL)