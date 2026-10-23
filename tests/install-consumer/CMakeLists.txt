cmake_minimum_required(VERSION 3.24)

# Minimal consumer of an installed sheller: the end-to-end judge for the delivery
# surface's "the install face is self-sufficient" requirement. It is configured
# from an install prefix alone, it links the packaged target, and it runs real
# analyses across the boundary (a std::string_view out of
# unicorn_version_string(), and two std::expected returns carrying std::vector,
# std::string and std::filesystem::path).
#
# It is NOT part of the default test set: it needs an installed prefix, which a
# normal build does not have. tests/install-consumer/run.cmake drives it.
project(sheller_install_consumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Nothing above the line refers to a source tree: no add_subdirectory, no
# FetchContent, no vcpkg, no hand-written include path. One package call.
find_package(sheller CONFIG REQUIRED)

add_executable(install_consumer main.cpp)
target_link_libraries(install_consumer PRIVATE sheller::sheller)
