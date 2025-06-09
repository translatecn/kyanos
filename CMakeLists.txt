cmake_minimum_required(VERSION 3.30)
project(kyanos C)

set(CMAKE_C_STANDARD 11)
include_directories("./libbpf/src")
include_directories("./ebpf/headers")
include_directories("./bpf")
include_directories("./.output")
include_directories("./libbpf/include/uapi")

message(STATUS "Current architecture: ${CMAKE_SYSTEM_PROCESSOR}")

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    add_definitions("-D__TARGET_ARCH_x86")
    SET(CMAKE_C_FLAGS,"${CMAKE_C_FLAGS} -target amd64-linux-gnu")
    include_directories("./vmlinux/x86")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    add_definitions("-D__TARGET_ARCH_arm64")
    SET(CMAKE_C_FLAGS,"${CMAKE_C_FLAGS} -target arm64-linux-gnu")
    include_directories("./vmlinux/arm64")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    add_definitions("-D__TARGET_ARCH_arm64")
    SET(CMAKE_C_FLAGS,"${CMAKE_C_FLAGS} -target arm64-linux-gnu")
    include_directories("./vmlinux/arm64")

else ()
    message(STATUS "This is an unknown processor architecture.")
endif ()

add_library(ebpf-nftrace
        "bpf/openssl.h"
        "bpf/protocol_inference.h"
        "bpf/data_common.h"
        "bpf/pktlatency.h"
        "bpf/gotls.bpf.c"
)

