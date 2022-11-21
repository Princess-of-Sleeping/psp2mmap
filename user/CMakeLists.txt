cmake_minimum_required(VERSION 3.0)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(mmap_tester)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O2 -fno-inline -fno-builtin -fshort-wchar")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

set(VITA_MAKE_FSELF_FLAGS "${VITA_MAKE_FSELF_FLAGS} -a 0x2C00000000000005")

enable_language(C ASM)

include_directories(
)

link_directories(
  ${CMAKE_SOURCE_DIR}/build/psp2mmap/psp2mmap_stubs/
)

add_executable(${PROJECT_NAME}
  src/main.c
  src/sha256.c
)

add_dependencies(${PROJECT_NAME} psp2mmap_stubs)

target_link_libraries(${PROJECT_NAME}
  SceAppMgr_stub
  SceKernelThreadMgr_stub
  SceSysmem_stub
  SceLibKernel_stub
  SceIofilemgr_stub
  SceProcessmgr_stub
  psp2mmap_stub
)

set_target_properties(${PROJECT_NAME}
  PROPERTIES LINK_FLAGS "-nostdlib"
  COMPILE_FLAGS "-D__PSP2_USER__"
)

vita_create_self(${PROJECT_NAME}.self ${PROJECT_NAME}
  CONFIG exports.yml
  UNSAFE
  STRIPPED
  REL_OPTIMIZE
)

vita_create_vpk(mmap_tester.vpk "KMLDR0000" ${PROJECT_NAME}.self
  VERSION "01.00"
  NAME "mmap_tester"
)

vita_create_stubs(stubs_${PROJECT_NAME} ${PROJECT_NAME} exports.yml)
