# The analysis facade: the combined entry points (analyze / unpack_sample)
# as their own static library. It must NOT live in sheller_engine - the
# unpack pipeline links sheller_unpack PRIVATE, so a facade inside the
# engine would make engine -> unpack a cycle. The include path is attached
# here (usage-requirement propagation must not depend on how the engine
# links this library); the internal wiring needs the engine/behavior
# headers PRIVATE, mirroring sheller_unpack.
add_library(sheller_api STATIC
  wiring.h
  wiring.cpp
  analysis.cpp
  unpack.cpp)
target_include_directories(sheller_api
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>)
target_include_directories(sheller_api PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../engine"
  "${CMAKE_CURRENT_SOURCE_DIR}/../behavior")
target_link_libraries(sheller_api
  PUBLIC sheller_engine
  PRIVATE sheller_unpack
  PRIVATE sheller_capture)
sheller_apply_static_core(sheller_api)
