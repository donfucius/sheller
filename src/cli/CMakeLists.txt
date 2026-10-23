# spdlog is used header-only, with std::format and exception-free error handling.
FetchContent_GetProperties(spdlog)
if(NOT spdlog_POPULATED)
  FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.17.0)
  set(SPDLOG_USE_STD_FORMAT ON)
  set(SPDLOG_BUILD_EXAMPLE OFF)
  set(SPDLOG_BUILD_TESTS OFF)
  set(SPDLOG_BUILD_BENCH OFF)
  set(SPDLOG_INSTALL OFF)
  FetchContent_MakeAvailable(spdlog)
endif()

# CLI render layer: deterministic JSON formatting over the analysis facade's
# public artifact types. A static library so the test suites link the exact
# renderer the executable ships. Sources here consume public headers only -
# the CI include gate forbids reaching into internal headers.
add_library(sheller_cli_render STATIC
  render.h
  render.cpp)
target_include_directories(sheller_cli_render
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
# No library on the link line: every name render.cpp reaches is inline in a
# public header (read_event/read_preamble/read_param_record/read_syscall/
# read_api_call/event_type_name/module_name_of/section_name_of), so the render
# layer has zero library-symbol dependencies - measured, its object has no
# undefined sheller:: symbol at all. The include dir it used to inherit from
# sheller_api is therefore re-exported directly, and the test suites that
# co-link this library keep staying out of the shared library's runtime debt.
target_include_directories(sheller_cli_render
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>)
sheller_apply_common(sheller_cli_render)

add_executable(sheller
  main.cpp
  log.cpp
  log.h)

# One binary, one link route: the executable is a consumer of the
# shared interface library and links no static core library. A leftover
# reference to the core would surface here as an unresolved symbol at link
# time, not as a second copy of the process state at run time.
target_link_libraries(sheller
  PRIVATE sheller_shared
  PRIVATE sheller_cli_render
  PRIVATE CLI11::CLI11
  PRIVATE spdlog::spdlog_header_only)
target_compile_definitions(sheller PRIVATE
  SPDLOG_USE_STD_FORMAT
  SPDLOG_NO_EXCEPTIONS)
# Keep spdlog headers out of first-party warning diagnostics.
target_include_directories(sheller SYSTEM PRIVATE "${spdlog_SOURCE_DIR}/include")
sheller_apply_common(sheller)

# The CLI ships as part of the delivery surface: it is the reference host, and a
# prefix without it cannot be run at all. On Linux it resolves libsheller.so.0
# through the $ORIGIN-relative install RPATH the root sets, so no environment
# variable is part of "installed" (specs/delivery-surface, "安装面自足"); on
# Windows the DLLs it needs land in the same bin/ directory.
install(TARGETS sheller
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
