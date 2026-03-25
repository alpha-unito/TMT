cmake_minimum_required(VERSION 3.16)
project(TMTLogger LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

#######################
# --- Global Paths ---
#######################

set(GENERATED_INCLUDE_DIR "${CMAKE_BINARY_DIR}/include")
file(MAKE_DIRECTORY ${GENERATED_INCLUDE_DIR})

#######################
# --- Dependencies ---
#######################

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

find_program(BPFTOOL_EXECUTABLE NAMES bpftool REQUIRED)
find_program(CLANG_EXECUTABLE NAMES clang REQUIRED)
find_program(GNUPLOT_EXECUTABLE NAMES gnuplot)

#######################
# --- External Libraries ---
#######################

include(FetchContent)
FetchContent_Declare(args
        GIT_REPOSITORY https://github.com/Taywee/args.git
        GIT_TAG 6.4.7
)
set(ARGS_BUILD_EXAMPLE OFF CACHE INTERNAL "")
set(ARGS_BUILD_UNITTESTS OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(args)

#######################
# --- Configuration Time: vmlinux.h ---
#######################

set(VMLINUX_H "${GENERATED_INCLUDE_DIR}/vmlinux.h")
execute_process(
        COMMAND ${BPFTOOL_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux format c
        OUTPUT_FILE ${VMLINUX_H}
        RESULT_VARIABLE bpf_result
)
if (NOT bpf_result EQUAL 0)
    message(FATAL_ERROR "Failed to generate vmlinux.h: ${bpf_result}")
endif ()

#######################
# --- Subdirectories ---
#######################

add_subdirectory(include/bpf)
add_subdirectory(include/user)

if (GNUPLOT_EXECUTABLE)
    add_subdirectory(plots)
else ()
    message(WARNING "Unable to locate gnuplot executable. skipping addition of plot generation target")
endif ()