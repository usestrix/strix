cmake_minimum_required(VERSION 3.16)
project(strix_dsa_attack_path VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(strix_dsa
  src/types.cpp
  src/node.cpp
  src/edge.cpp
  src/graph.cpp
)
target_include_directories(strix_dsa PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
if(MSVC)
  target_compile_options(strix_dsa PRIVATE /W4)
else()
  target_compile_options(strix_dsa PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(strix_dsa_cli src/cli.cpp)
target_link_libraries(strix_dsa_cli PRIVATE strix_dsa)

add_executable(strix_dsa_tests tests/test_engine.cpp)
target_link_libraries(strix_dsa_tests PRIVATE strix_dsa)

enable_testing()
add_test(NAME strix_dsa_unit_tests COMMAND strix_dsa_tests)

# Copy simulated sample data next to the CLI for convenient local demos.
add_custom_command(
  TARGET strix_dsa_cli POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:strix_dsa_cli>/data
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          ${CMAKE_CURRENT_SOURCE_DIR}/data/simulated_lab_network.txt
          $<TARGET_FILE_DIR:strix_dsa_cli>/data/simulated_lab_network.txt
)
