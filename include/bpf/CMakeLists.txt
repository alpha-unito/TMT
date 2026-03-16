set(BPF_BIN_DIR "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}") # Keep objects in /bin
file(GLOB BPF_SOURCES "${CMAKE_SOURCE_DIR}/src/bpf/*.c")
set(BPF_OBJECTS "")

foreach (src ${BPF_SOURCES})
    get_filename_component(name ${src} NAME_WE)
    set(obj "${BPF_BIN_DIR}/${name}.o")

    add_custom_command(
            OUTPUT ${obj}
            COMMAND ${CLANG_EXECUTABLE} -O2 -g -target bpf -D__TARGET_ARCH_x86
            -I${GENERATED_INCLUDE_DIR}
            -I${CMAKE_SOURCE_DIR}/include/bpf
            -I${CMAKE_SOURCE_DIR}/include
            -c ${src} -o ${obj}
            DEPENDS ${src}
            COMMENT "Building BPF object ${name}.o"
            VERBATIM
    )
    list(APPEND BPF_OBJECTS ${obj})
endforeach ()

add_custom_target(bpf_programs ALL DEPENDS ${BPF_OBJECTS})