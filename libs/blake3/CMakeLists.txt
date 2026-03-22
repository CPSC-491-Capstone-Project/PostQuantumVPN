cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(libblake3
  VERSION 1.8.3
  DESCRIPTION "BLAKE3 C implementation"
  LANGUAGES C ASM
)

# ---------- Architecture detection ----------
set(BLAKE3_AMD64_NAMES amd64 AMD64 x86_64)
set(BLAKE3_X86_NAMES   i686 x86 X86)
set(BLAKE3_ARMv8_NAMES aarch64 AArch64 arm64 ARM64 armv8 armv8a)

# ---------- Compiler flag defaults ----------
if(CMAKE_C_COMPILER_ID STREQUAL "GNU"
   OR CMAKE_C_COMPILER_ID STREQUAL "Clang"
   OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang")

  set(BLAKE3_CFLAGS_SSE2   "-msse2")
  set(BLAKE3_CFLAGS_SSE41  "-msse4.1")
  set(BLAKE3_CFLAGS_AVX2   "-mavx2")
  set(BLAKE3_CFLAGS_AVX512 "-mavx512f -mavx512vl")

  if(WIN32 OR CYGWIN)
    set(BLAKE3_AMD64_ASM_SOURCES
      blake3_avx2_x86-64_windows_gnu.S
      blake3_avx512_x86-64_windows_gnu.S
      blake3_sse2_x86-64_windows_gnu.S
      blake3_sse41_x86-64_windows_gnu.S
    )
  elseif(UNIX)
    set(BLAKE3_AMD64_ASM_SOURCES
      blake3_avx2_x86-64_unix.S
      blake3_avx512_x86-64_unix.S
      blake3_sse2_x86-64_unix.S
      blake3_sse41_x86-64_unix.S
    )
  endif()

  if(CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_ARMv8_NAMES
     AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(BLAKE3_CFLAGS_NEON "-mfpu=neon")
  endif()

elseif(MSVC)
  set(BLAKE3_CFLAGS_SSE2   "/arch:SSE2")
  set(BLAKE3_CFLAGS_SSE41  "/arch:AVX")
  set(BLAKE3_CFLAGS_AVX2   "/arch:AVX2")
  set(BLAKE3_CFLAGS_AVX512 "/arch:AVX512")

  set(BLAKE3_AMD64_ASM_SOURCES
    blake3_avx2_x86-64_windows_msvc.asm
    blake3_avx512_x86-64_windows_msvc.asm
    blake3_sse2_x86-64_windows_msvc.asm
    blake3_sse41_x86-64_windows_msvc.asm
  )
endif()

# ---------- SIMD type selection ----------
if(CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_AMD64_NAMES AND DEFINED BLAKE3_AMD64_ASM_SOURCES)
  set(BLAKE3_SIMD_TYPE "amd64-asm")
elseif(CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_X86_NAMES)
  set(BLAKE3_SIMD_TYPE "x86-intrinsics")
elseif(CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_ARMv8_NAMES
       AND (DEFINED BLAKE3_CFLAGS_NEON OR CMAKE_SIZEOF_VOID_P EQUAL 8))
  set(BLAKE3_SIMD_TYPE "neon-intrinsics")
else()
  set(BLAKE3_SIMD_TYPE "none")
endif()

message(STATUS "BLAKE3 SIMD type: ${BLAKE3_SIMD_TYPE}")

# ---------- Library target ----------
add_library(blake3 STATIC
  blake3.c
  blake3_dispatch.c
  blake3_portable.c
)

target_include_directories(blake3 PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

set_target_properties(blake3 PROPERTIES
  C_EXTENSIONS OFF
)

# ---------- SIMD sources ----------
if(BLAKE3_SIMD_TYPE STREQUAL "amd64-asm")
  target_sources(blake3 PRIVATE ${BLAKE3_AMD64_ASM_SOURCES})

elseif(BLAKE3_SIMD_TYPE STREQUAL "x86-intrinsics")
  target_sources(blake3 PRIVATE blake3_avx2.c blake3_avx512.c blake3_sse2.c blake3_sse41.c)
  set_source_files_properties(blake3_avx2.c   PROPERTIES COMPILE_FLAGS "${BLAKE3_CFLAGS_AVX2}")
  set_source_files_properties(blake3_avx512.c PROPERTIES COMPILE_FLAGS "${BLAKE3_CFLAGS_AVX512}")
  set_source_files_properties(blake3_sse2.c   PROPERTIES COMPILE_FLAGS "${BLAKE3_CFLAGS_SSE2}")
  set_source_files_properties(blake3_sse41.c  PROPERTIES COMPILE_FLAGS "${BLAKE3_CFLAGS_SSE41}")

elseif(BLAKE3_SIMD_TYPE STREQUAL "neon-intrinsics")
  target_sources(blake3 PRIVATE blake3_neon.c)
  target_compile_definitions(blake3 PRIVATE BLAKE3_USE_NEON=1)
  if(DEFINED BLAKE3_CFLAGS_NEON)
    set_source_files_properties(blake3_neon.c PROPERTIES COMPILE_FLAGS "${BLAKE3_CFLAGS_NEON}")
  endif()

elseif(BLAKE3_SIMD_TYPE STREQUAL "none")
  target_compile_definitions(blake3 PRIVATE
    BLAKE3_USE_NEON=0 BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512
  )
endif()