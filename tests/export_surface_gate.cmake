# Export-surface gate: the dynamic interface library must export exactly the
# checked-in set of product entries - symbol by symbol, not by count. A count
# check would pass while shipping the wrong names (a dropped SHELLER_API
# balanced by an internal symbol that leaked in), and it would report "6 != 7"
# where this reports which symbol.
#
# Invoked as a ctest command (see tests/CMakeLists.txt):
#   -DGATE_LIBRARY=$<TARGET_FILE:sheller_shared>
#   -DEXPECTED_LIST=<the list file for this platform>
#   -DGATE_TMP_DIR=<a writable build directory>
#   Linux:   -DNM_EXECUTABLE=... -DCXXFILT_EXECUTABLE=...
#   Windows: -DMSVC_TOOL_DIR=<the directory holding cl.exe/link.exe>
#
# Missing tools, an unreadable library or an empty symbol face are hard errors:
# a gate that silently finds nothing to compare is how an export regression
# ships.
#
# An entry containing ';' would split a CMake list element when the list file is
# read; the "exactly six entries" assertion below is what catches that.

# Script mode (-P) inherits no cmake_minimum_required, so on CMake below 4 the
# policies default to OLD and IN_LIST stops being an operator. Say it explicitly
# - the gate must behave the same on 3.25 (WSL), 3.28 (CI) and 4.x (local
# Windows), and a silently-OLD policy is exactly the kind of thing that turns a
# gate green on one host and broken on another.
cmake_policy(SET CMP0057 NEW)

if(NOT GATE_LIBRARY OR NOT EXPECTED_LIST)
  message(FATAL_ERROR "export_surface gate: -DGATE_LIBRARY and -DEXPECTED_LIST are required")
endif()
if(NOT EXISTS "${GATE_LIBRARY}")
  message(FATAL_ERROR "export_surface gate: library not found: ${GATE_LIBRARY}")
endif()
if(NOT EXISTS "${EXPECTED_LIST}")
  message(FATAL_ERROR "export_surface gate: expected list not found: ${EXPECTED_LIST}")
endif()
if(NOT GATE_TMP_DIR)
  set(GATE_TMP_DIR "${CMAKE_CURRENT_LIST_DIR}")
endif()

# ---------------------------------------------------------------- expected side
file(STRINGS "${EXPECTED_LIST}" expected_lines)
set(expected "")
foreach(line IN LISTS expected_lines)
  string(STRIP "${line}" stripped)
  if(stripped AND NOT stripped MATCHES "^#")
    list(APPEND expected "${stripped}")
  endif()
endforeach()
list(LENGTH expected expected_count)
if(NOT expected_count EQUAL 6)
  message(FATAL_ERROR
    "export_surface gate: ${EXPECTED_LIST} carries ${expected_count} entries, "
    "the product surface is exactly six")
endif()
list(REMOVE_DUPLICATES expected)
list(SORT expected)

# ----------------------------------------------------------------- actual face
# Both tools print CRLF on Windows; a stray \r inside a symbol name would make
# every comparison fail, so strip it before splitting into lines.
function(gate_split output var_name)
  string(REGEX REPLACE "\r" "" clean "${${var_name}}")
  string(REGEX REPLACE "\n" ";" lines "${clean}")
  set(${output} "${lines}" PARENT_SCOPE)
endfunction()

set(actual "")
if(WIN32)
  # dumpbin/undname come from the toolchain directory, never from PATH: the
  # windows CI job runs with shell: cmd, where the VS tools are not on PATH.
  if(NOT MSVC_TOOL_DIR)
    message(FATAL_ERROR "export_surface gate: -DMSVC_TOOL_DIR is required on Windows")
  endif()
  # Tools come from the configured toolchain directory first - the windows CI
  # job runs with shell: cmd, where the VS tools are not on PATH - and fall back
  # to a PATH search for setups whose linker is not MSVC's (Ninja + clang-cl,
  # lld-link), where the sibling lookup finds nothing.
  function(gate_resolve_tool out name dir)
    set(sibling "${dir}/${name}.exe")
    if(EXISTS "${sibling}")
      set(${out} "${sibling}" PARENT_SCOPE)
      return()
    endif()
    find_program(resolved NAMES "${name}.exe" "${name}")
    if(NOT resolved)
      message(FATAL_ERROR
        "export_surface gate: ${name} was not found next to the configured "
        "linker (${dir}) nor on PATH")
    endif()
    set(${out} "${resolved}" PARENT_SCOPE)
  endfunction()
  gate_resolve_tool(dumpbin dumpbin "${MSVC_TOOL_DIR}")
  gate_resolve_tool(undname undname "${MSVC_TOOL_DIR}")

  execute_process(COMMAND "${dumpbin}" /exports /nologo "${GATE_LIBRARY}"
                  RESULT_VARIABLE status
                  OUTPUT_VARIABLE dumpout
                  ERROR_VARIABLE dumperr)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "export_surface gate: dumpbin failed (${status}): ${dumperr}")
  endif()
  # An export row reads "ordinal hint RVA name". Requiring the two numeric
  # columns ahead of the hex RVA keeps the header (" ordinal hint RVA name"),
  # the counters ("           6 number of names") and the Characteristics row
  # ("    00000000 characteristics") out of the set. The name is the first
  # whitespace-delimited token: a Debug DLL's incremental-link export row
  # appends an alias fingerprint - "name = @ILT+5110(?name...)" - and feeding
  # that suffix to undname makes it echo the raw string instead of demangling
  # the name.
  gate_split(dump_lines dumpout)
  set(mangled "")
  foreach(line IN LISTS dump_lines)
    if(line MATCHES "^[ \t]*[0-9]+[ \t]+[0-9]+[ \t]+[0-9a-fA-F]+[ \t]+([^ \t]+)")
      list(APPEND mangled "${CMAKE_MATCH_1}")
    endif()
  endforeach()
  if(NOT mangled)
    message(FATAL_ERROR "export_surface gate: dumpbin reported no exports in ${GATE_LIBRARY}")
  endif()

  execute_process(COMMAND "${undname}" ${mangled}
                  RESULT_VARIABLE status
                  OUTPUT_VARIABLE undout
                  ERROR_VARIABLE underr)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "export_surface gate: undname failed (${status}): ${underr}")
  endif()
  # Each name decodes to a pair of lines; the result line is 'is :- "<form>"'.
  gate_split(und_lines undout)
  foreach(line IN LISTS und_lines)
    if(line MATCHES "^is :- \"(.*)\"$")
      list(APPEND actual "${CMAKE_MATCH_1}")
    endif()
  endforeach()
else()
  if(NOT NM_EXECUTABLE OR NOT CXXFILT_EXECUTABLE)
    message(FATAL_ERROR
      "export_surface gate: -DNM_EXECUTABLE and -DCXXFILT_EXECUTABLE are required")
  endif()
  foreach(tool "${NM_EXECUTABLE}" "${CXXFILT_EXECUTABLE}")
    if(NOT IS_ABSOLUTE "${tool}")
      message(FATAL_ERROR
        "export_surface gate: pass the resolved tool path (find_program result), got ${tool}")
    endif()
  endforeach()

  execute_process(COMMAND "${NM_EXECUTABLE}" -D --defined-only "${GATE_LIBRARY}"
                  RESULT_VARIABLE status
                  OUTPUT_VARIABLE nmout
                  ERROR_VARIABLE nmerr)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "export_surface gate: nm failed (${status}): ${nmerr}")
  endif()
  # c++filt reads stdin; INPUT_FILE wants a path, so park the nm output in the
  # build tree (the gate runs under ctest, where the directory exists).
  set(nm_tmp "${GATE_TMP_DIR}/export_surface_nm.txt")
  file(WRITE "${nm_tmp}" "${nmout}")
  execute_process(COMMAND "${CXXFILT_EXECUTABLE}"
                  INPUT_FILE "${nm_tmp}"
                  RESULT_VARIABLE status
                  OUTPUT_VARIABLE filtout
                  ERROR_VARIABLE filtterr)
  file(REMOVE "${nm_tmp}")
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "export_surface gate: c++filt failed (${status}): ${filtterr}")
  endif()
  # ' T ' only: defined text symbols. Weak/vague-linkage entries and data symbols
  # are not product entries, and the public headers' inline functions land there.
  string(REGEX REPLACE "\r" "" filtout "${filtout}")
  string(REGEX REPLACE "\n" ";" filtout_lines "${filtout}")
  foreach(line IN LISTS filtout_lines)
    if(line MATCHES "^[0-9a-fA-F]+ T (.*)$")
      list(APPEND actual "${CMAKE_MATCH_1}")
    endif()
  endforeach()
endif()

list(LENGTH actual actual_count)
if(NOT actual_count)
  message(FATAL_ERROR "export_surface gate: read no exported symbols from ${GATE_LIBRARY}")
endif()
list(SORT actual)

# --------------------------------------------------------------------- the diff
set(extra "")
set(missing "")
foreach(symbol IN LISTS actual)
  if(NOT "${symbol}" IN_LIST expected)
    list(APPEND extra "${symbol}")
  endif()
endforeach()
foreach(symbol IN LISTS expected)
  if(NOT "${symbol}" IN_LIST actual)
    list(APPEND missing "${symbol}")
  endif()
endforeach()

if(extra OR missing)
  set(report "export_surface gate: the dynamic face of ${GATE_LIBRARY} drifted")
  foreach(symbol IN LISTS extra)
    string(APPEND report "\n  exported but not on the product surface: ${symbol}")
  endforeach()
  foreach(symbol IN LISTS missing)
    string(APPEND report "\n  missing from the export face: ${symbol}")
  endforeach()
  string(APPEND report "\n  (expected list: ${EXPECTED_LIST})")
  message(FATAL_ERROR "${report}")
endif()

message(STATUS "export_surface gate: ${actual_count} exports, exactly the checked-in set")
