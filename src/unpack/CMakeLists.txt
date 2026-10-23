target_sources(sheller_engine PRIVATE unpack.cpp)

# The IAT repair pipeline: the export mapping is engine-native
# (no peconv), so the pipeline is portable and the CLI exposes the repair
# subcommand (and the loader-route unpack mode) on every platform.
add_library(sheller_unpack STATIC
  exports_mapper.cpp
  exports_mapper.h
  repair.cpp
  repair.h)
target_include_directories(sheller_unpack PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../engine"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include")
target_link_libraries(sheller_unpack
  PRIVATE sheller_engine)
sheller_apply_static_core(sheller_unpack)
