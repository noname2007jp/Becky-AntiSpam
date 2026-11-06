cmake_minimum_required(VERSION 3.20)
project(BeckyAntiSpam LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(antispam_engine
    src/engine/antispam.cpp
)
target_include_directories(antispam_engine PUBLIC src/engine)
if(MSVC)
    target_compile_options(antispam_engine PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(antispam_engine PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(antispam_tests tests/engine_tests.cpp)
target_link_libraries(antispam_tests PRIVATE antispam_engine)
enable_testing()
add_test(NAME antispam_engine_tests COMMAND antispam_tests)
