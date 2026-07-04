cmake_minimum_required(VERSION 3.20)

# =============================================================================
# StyxLoaderX — Windows x64 Injection Research Framework
# =============================================================================
# Build system (refactor series, decision D5 = CMake).
#
# Replaces the legacy run_project.bat with a standard CMake build that:
#   - Uses find_package(OpenSSL) instead of hardcoded C:\OpenSSL paths.
#   - Uses enable_language(ASM_MASM) to orchestrate ml64.exe for the
#     direct syscall stubs (modules/asm/styx_syscalls.asm).
#   - Uses add_custom_command to invoke nasm for the shellcode
#     (shellcode/shellcode.asm) — produces shellcode.bin as a data file.
#   - Enforces C++17 and treat-warnings-as-errors for the library and
#     tools.
#   - Requires x64 architecture (the techniques are x64-specific).
#
# Recommended usage with vcpkg:
#   cmake -B build -S . \
#         -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
#   cmake --build build --config Release
#
# Or with a system OpenSSL:
#   cmake -B build -S . -DOPENSSL_ROOT_DIR=C:/OpenSSL
#   cmake --build build --config Release

project(StyxLoaderX
    VERSION 0.2.0
    DESCRIPTION "Windows x64 Injection Research Framework"
    LANGUAGES CXX)

# -----------------------------------------------------------------------------
# Architecture check — these techniques are x64-specific.
# -----------------------------------------------------------------------------
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR
        "StyxLoaderX requires a 64-bit build (the techniques use the x64 "
        "syscall ABI and PEB layout). Re-run CMake from a 64-bit developer "
        "prompt (e.g. 'x64 Native Tools Command Prompt for VS 2022').")
endif()

if(NOT WIN32)
    message(WARNING
        "StyxLoaderX is Windows-only. The build will fail on non-Windows "
        "platforms because the source uses <windows.h> and the MASM stubs "
        "require ml64.exe. Cross-compilation is not supported.")
endif()

# -----------------------------------------------------------------------------
# C++ standard and warning flags.
# -----------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /WX)
    # /W4 = high warning level
    # /permissive- = strict standards conformance
    # /WX = treat warnings as errors
    # Note: AES_cbc_encrypt deprecation warning (C4996) from OpenSSL 3.0
    # is suppressed at the source level in src/string_obfuscator.cpp via
    # a #pragma warning(disable: 4996), with a TODO for EVP migration.
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# -----------------------------------------------------------------------------
# Find OpenSSL (for AES string obfuscation).
# -----------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
message(STATUS "  include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "  libs: ${OPENSSL_LIBRARIES}")

# -----------------------------------------------------------------------------
# Enable MASM (Microsoft Macro Assembler) for the direct syscall stubs.
# ml64.exe is part of Visual Studio Build Tools (C++ workload).
# -----------------------------------------------------------------------------
enable_language(ASM_MASM)

# -----------------------------------------------------------------------------
# Find NASM for the shellcode (separate from MASM — NASM has different
# syntax and is used for the position-independent shellcode canary).
# -----------------------------------------------------------------------------
find_program(NASM_EXECUTABLE nasm)
if(NOT NASM_EXECUTABLE)
    message(FATAL_ERROR
        "NASM not found. Install from https://www.nasm.us/ and ensure it is "
        "on your PATH. NASM is used to assemble shellcode/shellcode.asm "
        "into shellcode.bin (the calc.exe canary).")
endif()
message(STATUS "NASM found: ${NASM_EXECUTABLE}")

# -----------------------------------------------------------------------------
# Library target: styxloader (static)
# Contains all the injection modules + MASM syscall stubs.
# -----------------------------------------------------------------------------
add_library(styxloader STATIC
    src/shellcode.cpp
    src/sandbox_check.cpp
    src/string_obfuscator.cpp
    src/simple_injector.cpp
    src/hollow_injector.cpp
    src/direct_syscall.cpp
    modules/asm/styx_syscalls.asm
)
target_include_directories(styxloader PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(styxloader PUBLIC
    OpenSSL::Crypto
    OpenSSL::SSL
)
# MASM flags: /Cp preserves case (needed for extern symbol matching).
set_source_files_properties(
    modules/asm/styx_syscalls.asm
    PROPERTIES
        COMPILE_FLAGS "/nologo /Cp"
)

# -----------------------------------------------------------------------------
# Executable: main_loader (full orchestrator)
# -----------------------------------------------------------------------------
add_executable(main_loader
    tools/main_loader.cpp
)
target_link_libraries(main_loader PRIVATE styxloader)

# -----------------------------------------------------------------------------
# Executable: simple_injector_tool (standalone baseline injector)
# -----------------------------------------------------------------------------
add_executable(simple_injector_tool
    tools/simple_injector_tool.cpp
)
target_link_libraries(simple_injector_tool PRIVATE styxloader)

# -----------------------------------------------------------------------------
# Shellcode canary: produce shellcode.bin via NASM
# This is a data file, not a binary target — it is consumed at runtime by
# main_loader.exe / simple_injector_tool.exe as the payload to inject.
# -----------------------------------------------------------------------------
add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/shellcode.bin
    COMMAND
        ${NASM_EXECUTABLE} -f bin
            ${CMAKE_CURRENT_SOURCE_DIR}/shellcode/shellcode.asm
            -o ${CMAKE_CURRENT_BINARY_DIR}/shellcode.bin
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/shellcode/shellcode.asm
    COMMENT "Assembling shellcode.asm -> shellcode.bin (NASM)"
    VERBATIM
)
add_custom_target(shellcode_bin ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/shellcode.bin
)

# -----------------------------------------------------------------------------
# Post-build: copy OpenSSL DLLs next to the .exe (audit fix F18)
# Without this, main_loader.exe crashes at runtime with 'DLL not found'
# because it links against libcrypto.lib / libssl.lib (import libraries)
# which forward to libcrypto-3-x64.dll / libssl-3-x64.dll at runtime.
# -----------------------------------------------------------------------------
if(OPENSSL_INCLUDE_DIR)
    get_filename_component(OPENSSL_BIN_DIR "${OPENSSL_INCLUDE_DIR}/../bin" ABSOLUTE)
    foreach(dll_name libcrypto-3-x64.dll libssl-3-x64.dll)
        if(EXISTS "${OPENSSL_BIN_DIR}/${dll_name}")
            add_custom_command(TARGET main_loader POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${OPENSSL_BIN_DIR}/${dll_name}"
                    $<TARGET_FILE_DIR:main_loader>)
            add_custom_command(TARGET simple_injector_tool POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${OPENSSL_BIN_DIR}/${dll_name}"
                    $<TARGET_FILE_DIR:simple_injector_tool>)
            message(STATUS "  will deploy ${dll_name} at build time")
        endif()
    endforeach()
endif()

# -----------------------------------------------------------------------------
# Print build summary
# -----------------------------------------------------------------------------
message(STATUS "")
message(STATUS "StyxLoaderX build configuration:")
message(STATUS "  C++ standard:    ${CMAKE_CXX_STANDARD}")
message(STATUS "  Architecture:    x64 (verified)")
message(STATUS "  OpenSSL:         ${OPENSSL_VERSION}")
message(STATUS "  NASM:            ${NASM_EXECUTABLE}")
message(STATUS "  MASM (ml64):     ${CMAKE_ASM_MASM_COMPILER}")
message(STATUS "  Targets:")
message(STATUS "    styxloader (static lib)")
message(STATUS "    main_loader (exe)")
message(STATUS "    simple_injector_tool (exe)")
message(STATUS "    shellcode.bin (data file, via NASM)")
message(STATUS "")
