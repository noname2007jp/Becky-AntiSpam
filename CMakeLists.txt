cmake_minimum_required(VERSION 3.20)
project(BeckyAntiSpam LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
FetchContent_Declare(
    sqlite3
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip
    URL_HASH SHA3_256=92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30
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
    src/engine/tokenizer.cpp
    src/parser/message_parser.cpp
    src/crypto/sha256.cpp
)
target_include_directories(antispam_engine PUBLIC src/engine src/parser src/crypto)
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

add_library(antispam_pipeline
    src/pipeline/mail_pipeline.cpp
)
target_include_directories(antispam_pipeline PUBLIC src/pipeline)
target_link_libraries(antispam_pipeline PUBLIC antispam_engine antispam_storage)
if(MSVC)
    target_compile_options(antispam_pipeline PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(antispam_pipeline PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
        message(FATAL_ERROR "Becky! is 32-bit; BeckyAntiSpam plugin must be built with Win32/x86.")
    endif()

    add_library(becky_antispam_plugin SHARED
        src/plugin/plugin.cpp
        src/plugin/BeckyAntiSpam.def
    )
    target_include_directories(becky_antispam_plugin PRIVATE
        src/engine src/parser src/storage src/pipeline
    )
    target_link_libraries(becky_antispam_plugin PRIVATE antispam_pipeline shell32)
    set_target_properties(becky_antispam_plugin PROPERTIES
        PREFIX ""
        OUTPUT_NAME "BeckyAntiSpam"
    )
    if(MSVC)
        target_compile_options(becky_antispam_plugin PRIVATE /W4 /permissive- /utf-8)
    endif()
endif()

add_executable(antispam_tests tests/engine_tests.cpp)
target_link_libraries(antispam_tests PRIVATE antispam_engine antispam_storage antispam_pipeline)
enable_testing()
add_test(NAME antispam_engine_tests COMMAND antispam_tests)
