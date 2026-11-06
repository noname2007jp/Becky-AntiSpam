cmake_minimum_required(VERSION 3.20)
project(BeckyAntiSpam LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)
FetchContent_Declare(
    sqlite3
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip
)
FetchContent_GetProperties(sqlite3)
if(NOT sqlite3_POPULATED)
    FetchContent_Populate(sqlite3)
endif()

add_library(sqlite3 STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${sqlite3_SOURCE_DIR})
target_compile_definitions(sqlite3 PRIVATE SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION=1)

add_library(antispam_engine
    src/engine/antispam.cpp
)
target_include_directories(antispam_engine PUBLIC src/engine)
if(MSVC)
    target_compile_options(antispam_engine PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(antispam_engine PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_library(antispam_storage
    src/storage/sqlite_store.cpp
)
target_include_directories(antispam_storage PUBLIC src/storage)
target_link_libraries(antispam_storage PUBLIC antispam_engine sqlite3)
if(MSVC)
    target_compile_options(antispam_storage PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(antispam_storage PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(antispam_tests tests/engine_tests.cpp)
target_link_libraries(antispam_tests PRIVATE antispam_engine antispam_storage)
enable_testing()
add_test(NAME antispam_engine_tests COMMAND antispam_tests)
