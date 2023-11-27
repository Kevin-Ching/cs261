cmake_minimum_required(VERSION 3.13)

project(tests)

add_executable(tests)
target_sources(tests PRIVATE 
    src/tests.cpp src/tests.h 
    src/my_utils.cpp src/my_utils.h
    src/integer_dot_product.cpp
    src/float_dot_product.cpp
)

add_subdirectory(SEAL)
target_link_libraries(tests PUBLIC seal)
target_include_directories(tests PUBLIC SEAL)
# target_link_directories(tests PRIVATE SEAL)