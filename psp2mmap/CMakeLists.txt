cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(psp2mmap)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O2 -fno-inline")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

enable_language(C ASM)

link_directories(
  # ${CMAKE_SOURCE_DIR}/extra/
)

add_executable(psp2mmap
  src/mmap.c
  src/mmap_excp.c
  src/mmap_excp_handler.S
  src/mmap_syscall.c
)

target_link_libraries(psp2mmap
  SceCpuForDriver_stub
  SceDebugForDriver_stub
  SceExcpmgrForKernel_stub
  SceIofilemgrForDriver_stub
  SceModulemgrForDriver_stub
  SceProcEventForDriver_stub
  SceSysclibForDriver_stub
  SceSysmemForDriver_stub
  SceThreadmgrForDriver_stub
  taihenModuleUtils_stub
)

set_target_properties(psp2mmap
  PROPERTIES LINK_FLAGS "-nostdlib"
  COMPILE_FLAGS "-D__PSP2_KERNEL__"
)

vita_create_self(psp2mmap.skprx psp2mmap
  CONFIG exports.yml
  UNSAFE
  STRIPPED
  REL_OPTIMIZE
)

vita_create_stubs(psp2mmap_stubs psp2mmap exports.yml KERNEL)
