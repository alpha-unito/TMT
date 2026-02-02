cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


project(
        "Thread Monitoring Tool"
        VERSION 1.0.0
        DESCRIPTION "Transparently monitor threading behaviour in multithreaded applications"
        LANGUAGES C CXX
)

# ------------------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------------------

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(BPF_DIR ${SRC_DIR}/bpf)
set(USER_DIR ${SRC_DIR}/user)

set(BIN_DIR ${CMAKE_BINARY_DIR}/bin)
set(OUT_DIR ${CMAKE_SOURCE_DIR}/out)

set(BUILD_INCLUDE_DIR ${CMAKE_BINARY_DIR}/include)
set(BPF_BUILD_INC_DIR ${BUILD_INCLUDE_DIR}/bpf)
set(VMLINUX_H ${BPF_BUILD_INC_DIR}/vmlinux.h)

set(SRC_BPF_INC_DIR ${CMAKE_SOURCE_DIR}/include/bpf)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

file(MAKE_DIRECTORY
        ${BIN_DIR}
        ${OUT_DIR}
        ${BPF_BUILD_INC_DIR}
        ${SRC_BPF_INC_DIR}
)

# ------------------------------------------------------------------------------
# BPF sources
# ------------------------------------------------------------------------------

set(BPF_SOURCES
        execve.bpf.c
        fork.bpf.c
        exit.bpf.c
        clone.bpf.c
        clone3.bpf.c
        exit_group.bpf.c
        sched_switch.bpf.c
)

list(TRANSFORM BPF_SOURCES PREPEND ${BPF_DIR}/)

# ------------------------------------------------------------------------------
# vmlinux.h generation
# ------------------------------------------------------------------------------

find_program(BPFTOOL_EXECUTABLE NAMES bpftool REQUIRED)

add_custom_command(
        OUTPUT ${VMLINUX_H}
        COMMAND ${BPFTOOL_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux format c
        > ${VMLINUX_H}
        COMMENT "Generating vmlinux.h"
        VERBATIM
)

add_custom_target(vmlinux_h DEPENDS ${VMLINUX_H})

add_custom_command(
        TARGET vmlinux_h POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${VMLINUX_H}
        ${SRC_BPF_INC_DIR}/vmlinux.h
        COMMENT "Copying vmlinux.h to source include directory"
)

# ------------------------------------------------------------------------------
# BPF object compilation
# ------------------------------------------------------------------------------

set(BPF_OBJECTS)

foreach (bpf_src IN LISTS BPF_SOURCES)
    get_filename_component(bpf_name ${bpf_src} NAME_WE)
    string(REPLACE ".bpf" "" bpf_name ${bpf_name})

    set(bpf_obj ${BIN_DIR}/${bpf_name}.bpf.o)

    add_custom_command(
            OUTPUT ${bpf_obj}
            COMMAND clang
            -O2 -g -target bpf -D__TARGET_ARCH_x86
            -I${SRC_BPF_INC_DIR}
            -I${BPF_BUILD_INC_DIR}
            -I/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu
            -c ${bpf_src}
            -o ${bpf_obj}
            DEPENDS ${bpf_src} vmlinux_h
            COMMENT "Building BPF object ${bpf_name}.bpf.o"
            VERBATIM
    )

    list(APPEND BPF_OBJECTS ${bpf_obj})
endforeach ()

add_custom_target(bpf_objects ALL DEPENDS ${BPF_OBJECTS})

# ------------------------------------------------------------------------------
# args (FetchContent)
# ------------------------------------------------------------------------------

include(FetchContent)

FetchContent_Declare(
        args
        GIT_REPOSITORY https://github.com/Taywee/args.git
        GIT_TAG 6.4.7
)

set(ARGS_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(ARGS_BUILD_UNITTESTS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(args)

# ------------------------------------------------------------------------------
# Userland executable
# ------------------------------------------------------------------------------

set(USER_SOURCES
        ${CMAKE_SOURCE_DIR}/main.cpp
        ${USER_DIR}/logger/SyscallLogger.cpp
        ${USER_DIR}/processors/EventProcessor.cpp
        ${USER_DIR}/processors/SwitchProcessor.cpp
        ${USER_DIR}/handlers/BaseHandler.cpp
        ${USER_DIR}/handlers/ExecveHandler.cpp
        ${USER_DIR}/handlers/ForkHandler.cpp
        ${USER_DIR}/handlers/ExitHandler.cpp
        ${USER_DIR}/handlers/CloneHandler.cpp
        ${USER_DIR}/handlers/Clone3Handler.cpp
        ${USER_DIR}/handlers/ExitGroupHandler.cpp
        ${USER_DIR}/handlers/SwitchHandler.cpp
)

add_executable(tmt_logger ${USER_SOURCES})
add_dependencies(tmt_logger bpf_objects)

target_include_directories(tmt_logger PRIVATE
        ${USER_DIR}
        ${CMAKE_SOURCE_DIR}/include/user/common
        ${CMAKE_SOURCE_DIR}/include/user/handlers
        ${CMAKE_SOURCE_DIR}/include/user/logger
        ${CMAKE_SOURCE_DIR}/include/user/processors
)

target_link_libraries(tmt_logger PRIVATE args)

# ------------------------------------------------------------------------------
# libbpf / threads
# ------------------------------------------------------------------------------

find_package(Threads REQUIRED)
find_package(PkgConfig)

if (PKG_CONFIG_FOUND)
    pkg_check_modules(LIBBPF libbpf)
endif ()

if (LIBBPF_FOUND)
    target_include_directories(tmt_logger PRIVATE ${LIBBPF_INCLUDE_DIRS})
    target_link_libraries(tmt_logger PRIVATE ${LIBBPF_LIBRARIES})
else ()
    target_link_libraries(tmt_logger PRIVATE bpf elf z)
endif ()

target_link_libraries(tmt_logger PRIVATE Threads::Threads)

target_link_directories(tmt_logger PRIVATE /usr/lib64)

set_target_properties(tmt_logger PROPERTIES
        BUILD_RPATH "/usr/lib64;/usr/local/lib"
)

# ------------------------------------------------------------------------------
# Plotting (gnuplot)
# ------------------------------------------------------------------------------

option(TMT_ENABLE_PLOTS "Enable gnuplot plot targets" ON)

if (TMT_ENABLE_PLOTS)
    find_program(GNUPLOT_EXECUTABLE NAMES gnuplot)

    if (GNUPLOT_EXECUTABLE)
        set(PLOTS_DIR ${CMAKE_SOURCE_DIR}/plots)

        add_custom_target(plot_threads_over_time
                COMMAND ${GNUPLOT_EXECUTABLE}
                -c ${PLOTS_DIR}/threads_over_time.gp
                "${OUT_DIR}/oncpu_slices.csv"
                "${OUT_DIR}/alive_series.csv"
                "${OUT_DIR}/threads_over_time.png"
                DEPENDS tmt_logger
                COMMENT "Generating threads_over_time plot"
        )

        add_custom_target(plots_all DEPENDS plot_threads_over_time)
    else ()
        add_custom_target(plots_all
                COMMAND ${CMAKE_COMMAND} -E echo
                "Gnuplot not available. Install it and reconfigure."
        )
    endif ()
endif ()

# ------------------------------------------------------------------------------
# Convenience run target
# ------------------------------------------------------------------------------

add_custom_target(run
        COMMAND sudo -E $<TARGET_FILE:tmt_logger> --cmd "sleep 1" --print-raw
        DEPENDS tmt_logger
)
