project(SeeServExample LANGUAGES C)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

add_executable(SeeServExample ${CMAKE_CURRENT_SOURCE_DIR}/Main.c)
target_link_libraries(SeeServExample PRIVATE SeeServ)