file(GLOB_RECURSE USER_SOURCES "${CMAKE_SOURCE_DIR}/src/user/*.cpp")

add_executable(tmt_logger ${USER_SOURCES})
add_dependencies(tmt_logger bpf_programs)
add_compile_definitions(tmt_logger _USERSPACE)
target_compile_options(tmt_logger PRIVATE -Wall -Wextra -Wpedantic)

target_include_directories(tmt_logger PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include/user/
        ${CMAKE_SOURCE_DIR}/include/
        ${LIBBPF_INCLUDE_DIRS}
        ${args_SOURCE_DIR}
)

target_link_libraries(tmt_logger PRIVATE
        ${LIBBPF_LIBRARIES}
        Threads::Threads
        args
)


add_custom_target(run
        COMMAND sudo -E $<TARGET_FILE:tmt_logger> --cmd "sleep 1" --print-raw
        DEPENDS tmt_logger
        USES_TERMINAL
)