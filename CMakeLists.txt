cmake_minimum_required(VERSION 3.15)
project(cryptopp_brute LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)

find_package(cryptopp CONFIG REQUIRED)

# Botan 2.19.3 — no CMake config, use manual find
find_path(BOTAN_INCLUDE_DIR botan/block_cipher.h)
find_library(BOTAN_LIBRARY_RELEASE NAMES botan botan-2 PATHS "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib" NO_DEFAULT_PATH)
find_library(BOTAN_LIBRARY_DEBUG NAMES botan botan-2 PATHS "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/lib" NO_DEFAULT_PATH)
if(NOT BOTAN_LIBRARY_RELEASE)
    find_library(BOTAN_LIBRARY_RELEASE NAMES botan botan-2)
endif()
if(NOT BOTAN_INCLUDE_DIR OR NOT BOTAN_LIBRARY_RELEASE)
    message(FATAL_ERROR "Botan library not found")
endif()

add_executable(cryptopp_brute
    cryptopp_brute.cpp
    gladman_ciphers.cpp
    gladman_wrap_crypton.cpp
    gladman_wrap_dfc.cpp
    gladman_wrap_e2.cpp
    gladman_wrap_frog.cpp
    gladman_wrap_magenta.cpp
    gladman_wrap_hpc.cpp
    botan_ciphers.cpp
    standalone_ciphers.cpp
    standalone_wrap_clefia.cpp
    standalone_wrap_anubis.cpp
    standalone_wrap_khazad.cpp
    standalone_wrap_kuznyechik.cpp
)
target_include_directories(cryptopp_brute PRIVATE ${BOTAN_INCLUDE_DIR})
target_link_libraries(cryptopp_brute PRIVATE
    cryptopp::cryptopp
    $<$<CONFIG:Debug>:${BOTAN_LIBRARY_DEBUG}>
    $<$<NOT:$<CONFIG:Debug>>:${BOTAN_LIBRARY_RELEASE}>
    ws2_32 crypt32
)

if(MSVC)
    set_property(TARGET cryptopp_brute PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Copy built exe to project root so the GUI can find it
add_custom_command(TARGET cryptopp_brute POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:cryptopp_brute>
        ${CMAKE_SOURCE_DIR}/cryptopp_brute.exe
)
