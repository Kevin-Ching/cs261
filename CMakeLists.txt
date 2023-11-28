cmake_minimum_required(VERSION 3.13)

project(tests)

add_executable(tests)
target_sources(tests PRIVATE 
    src/tests.cpp src/tests.h 
    src/my_utils.cpp src/my_utils.h
    src/1_integer_dot_product.cpp
    src/2_float_dot_product.cpp
    src/3_float_matrix_vector.cpp
    src/4_packed_matrix_vector.cpp
    src/5_timed_packed_products.cpp
)

add_subdirectory(SEAL)
target_link_libraries(tests PUBLIC seal)
target_include_directories(tests PUBLIC SEAL)
# target_link_directories(tests PRIVATE SEAL)