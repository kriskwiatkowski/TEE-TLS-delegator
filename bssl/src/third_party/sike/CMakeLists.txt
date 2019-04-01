cmake_minimum_required(VERSION 2.8.11)
include_directories(../../include)

if(UNIX AND NOT APPLE)
    set(ASM_EXT S)
    enable_language(ASM)
else()
    set(OPENSSL_NO_ASM "1")
endif()

# Platform specific sources
if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64" AND NOT OPENSSL_NO_ASM)
    set(
        SIKE_PLATFORM_SOURCES

        src/asm/fp_x64_asm.${ASM_EXT}
    )
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64" OR ${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64" AND NOT OPENSSL_NO_ASM)
    set(
        SIKE_PLATFORM_SOURCES

        src/asm/fp_arm64_asm.${ASM_EXT}
    )
else()
    set(
        SIKE_PLATFORM_SOURCES

        src/asm/fp_generic.c
    )
    add_definitions(-DOPENSSL_NO_ASM)
endif()

# Compile to object files, we will link them with libssl
add_library(
    sike

    OBJECT

    src/isogeny.c
    src/fpx.c
    src/P503.c
    src/sike.c

    ${SIKE_PLATFORM_SOURCES}
)

target_include_directories(sike PUBLIC
  include
)

add_executable(
    sike_test

    src/sike_test.cc

  $<TARGET_OBJECTS:boringssl_gtest_main>
)

target_include_directories(sike_test PUBLIC
  include
)

target_link_libraries(sike_test test_support_lib boringssl_gtest crypto)
