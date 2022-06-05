cmake_minimum_required(VERSION 3.0)

project(SeeServ LANGUAGES C VERSION 1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Wall -Wextra -Wpedantic")

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(INCLUDE ${ROOT}/include)
set(SRC ${ROOT}/src)
set(LIB ${ROOT}/lib)

# build
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB})

file(GLOB_RECURSE sources "${INCLUDE}/*.h" "${SRC}/*.c")
add_library(SeeServ ${sources})
target_include_directories(SeeServ PUBLIC ${INCLUDE})

add_subdirectory(example)