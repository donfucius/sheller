# The shared interface library - the product surface. One translation unit
# (api.cpp) defines the public product names and forwards each to the internal
# name the static core carries; nothing here has a definition of its own. The
# resulting dynamic face is reconciled against a checked-in list by
# tests/export_surface_gate.cmake (ctest name: export_surface).
#
# Link-route invariant (spelled out in api.cpp): the CLI links this
# library and no static core library; the direct-link test suites link the
# static core and never a product name. A binary that mixed the two would carry
# two copies of the process state (the log sink is the visible one) and fail
# silently rather than at link time.
add_library(sheller_shared SHARED api.cpp guard.h)
# Both version fields derive from project(): a second place to remember is a
# second place that drifts, and here the thing remembered is a name the loader
# resolves (SONAME) - not a string in a document. SOVERSION is the major alone,
# so a patch or minor release swaps the file under libsheller.so.0 without
# requiring any consumer to re-link.
set_target_properties(sheller_shared PROPERTIES
  OUTPUT_NAME sheller
  EXPORT_NAME sheller
  VERSION "${PROJECT_VERSION}"
  SOVERSION "${PROJECT_VERSION_MAJOR}")
# PRIVATE, and the include dir re-exported separately: a PUBLIC link to a static
# library travels through this target's interface, so every consumer would put
# the whole static core on its own link line *next to* this .so/.dll and the
# linker would happily extract a second copy of it (measured: the CLI carried its
# own log_state, set_sink_impl and unpack pipeline - two process states, the one
# failure this layout exists to prevent). PRIVATE keeps the archives inside this
# library; the consumer gets the headers, and any leftover reference to a core
# symbol then shows up as an unresolved symbol at link time instead of being
# silently satisfied by a duplicate.
target_link_libraries(sheller_shared PRIVATE sheller_api)
# BUILD_INTERFACE for the source tree, INSTALL_INTERFACE for a prefix: without the
# second one an imported sheller::sheller carries no header directory, and the
# consumer has to write the include path by hand - which is the "no environment
# variable, no manual copy" clause of the delivery surface failing.
target_include_directories(sheller_shared PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# The forwarding layer reads the core's internal headers on purpose (the src/cli
# relative-parent ban does not reach here - see the note in api.cpp).
target_include_directories(sheller_shared PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../api"
  "${CMAKE_CURRENT_SOURCE_DIR}/../engine"
  "${CMAKE_CURRENT_SOURCE_DIR}/../runtime/capture")
# The only target that sees this define: everywhere else the SHELLER_API macro
# expands to the consumer shape, and MSVC then rejects a definition of the
# declaration - which is the mechanism keeping the public names out of the
# static archives.
target_compile_definitions(sheller_shared PRIVATE SHELLER_BUILDING_SHARED)
# The consumer-side configuration checks in include/sheller/export.h compare
# against how this library was really built, so the values travel as PUBLIC
# definitions: a consumer that mixes debug and release fails to compile instead
# of corrupting memory at run time. Only targets that link this library see them,
# which is exactly the set with a boundary to match - a static-core consumer
# compiles the core itself, in its own configuration.
# The literal 0 for _GLIBCXX_DEBUG states a fact about this tree: no CMake file
# anywhere defines it (grep-verified). If that ever changes, derive the value at
# configure time instead of hardcoding it here.
#
# SHELLER_LIB_ABI_DEBUG is ringed in BUILD_INTERFACE on purpose, and it is not
# decoration. Measured with a throwaway package and a throwaway consumer, on both
# platforms and both cmake versions: a
# PUBLIC definition spelled $<CONFIG:Debug> is exported into the package as that
# same generator expression and is then evaluated in the CONSUMER's configuration
# - a Debug consumer against an installed Release library read "1", matched its
# own _DEBUG, and the #error that exists because _ITERATOR_DEBUG_LEVEL changes
# std::string/std::vector layout while leaving the decorated name identical went
# quiet. Inside the tree the genex still says the right thing (both sides are the
# same configuration), so it stays there and only there; an installed tree gets
# the literal from shellerAbiConfig.cmake, which the install step writes with the
# configuration actually being installed. SHELLER_LIB_ABI_GLIBCXX_DEBUG is a
# constant, not a configuration reading, so it keeps being exported.
target_compile_definitions(sheller_shared PUBLIC
  $<BUILD_INTERFACE:SHELLER_LIB_ABI_DEBUG=$<CONFIG:Debug>>
  SHELLER_LIB_ABI_GLIBCXX_DEBUG=0)
if(NOT MSVC)
  # Two link/compile guards, both so the macro is the ONLY thing that can put a
  # name on the dynamic face:
  #   * hidden by default for this TU as well - without it every function
  #     defined here is exported whether or not it spells SHELLER_API, and the
  #     "an entry stopped being exported" case (a macro that expands to empty on
  #     one platform) would stay green on Linux while the gate catches it on
  #     Windows. With it, a missing attribute means a missing export on both.
  #   * --exclude-libs,ALL - the static core is already -fvisibility=hidden, but
  #     an archive member that opted out (or a third-party object linked in
  #     here) must not reach .dynsym either.
  target_compile_options(sheller_shared PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
  target_link_options(sheller_shared PRIVATE -Wl,--exclude-libs,ALL)
endif()
# Host-side glue: sheller_apply_common, not the engine's discipline - this TU
# keeps exceptions. The engine core is exception-free by a source-level rule
# (tests/engine_nothrow_gate.cmake) rather than by -fno-exceptions, so linking
# through here does not constrain what this layer may catch.
sheller_apply_common(sheller_shared)

if(WIN32)
  # CMake's applocal step copies vcpkg's third-party DLLs (unicorn, Zydis) next
  # to each consumer; it never handles a first-party one, so sheller.dll is
  # placed by hand. The generator expressions resolve at generate time, so the
  # targets named here may be defined in later directories.
  set(sheller_shared_deploy_dirs "$<TARGET_FILE_DIR:sheller>")
  if(SHELLER_BUILD_TESTS)
    # shared_api_test loads the library straight out of its own directory.
    list(APPEND sheller_shared_deploy_dirs "$<TARGET_FILE_DIR:shared_api_test>")
  endif()
  foreach(deploy_dir IN LISTS sheller_shared_deploy_dirs)
    # make_directory first: on a clean tree this target builds before its
    # consumers do, so the destination directory may not exist yet, and
    # copy_if_different into a missing directory is a hard error.
    add_custom_command(TARGET sheller_shared POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E make_directory "${deploy_dir}"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:sheller_shared>" "${deploy_dir}/"
      COMMENT "Deploying sheller.dll")
  endforeach()
endif()

# -----------------------------------------------------------------------------
# Installation (specs/delivery-surface). Only this target and the CLI are
# exported, and the export set carries nothing else: the static core is linked
# PRIVATE, so it does not travel into a consumer's interface. A PUBLIC link to a
# static library would put the whole core on every consumer's link line next to the
# shared library, and the linker would happily extract a second copy of the process
# state - invisible to every in-tree check, because no in-tree binary is what a host
# links. run.cmake is what looks at the installed consumer instead.
install(TARGETS sheller_shared
  EXPORT shellerTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  # No INCLUDES DESTINATION here: the $<INSTALL_INTERFACE:> above already puts the
  # header directory on the exported interface, and a second spelling of the same
  # path lands twice in the imported target's INTERFACE_INCLUDE_DIRECTORIES (the
  # generated shellerTargets.cmake is where that shows up). One place, one path.
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

if(WIN32)
  # The third-party runtimes are separate DLLs here, and include/sheller/export.h
  # already states that they must sit next to the consumer's executable - so
  # installing sheller.dll without them delivers something that cannot start
  # under its own published contract.
  #
  # The source is the directory the target was built in, not vcpkg's installed
  # tree: the applocal step above already picked the DLL that matches this
  # configuration, and $<TARGET_FILE_DIR:> resolves per configuration at install
  # time. Reading vcpkg's tree directly would have to re-implement that choice on
  # a generator that builds Debug and Release into the same directory.
  #
  # Linux has no equivalent: unicorn and Zydis are linked in there, and there is
  # nothing to deploy.
  install(FILES
    "$<TARGET_FILE_DIR:sheller_shared>/unicorn.dll"
    "$<TARGET_FILE_DIR:sheller_shared>/Zydis.dll"
    DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
