# Version reconciliation gate: the project version is written once, in project(),
# and everything derived from it has to agree or the build stops.
#
# What is derived, and therefore checked:
#   * the three macros in the public header (include/sheller/version.h) - the
#     compile-time version facts a consumer reads;
#   * the literal version_string() returns in that same header, which is the
#     version the CLI and the shipped binaries print;
#   * the library file name and the SONAME, which CMake derives from
#     ${PROJECT_VERSION} / ${PROJECT_VERSION_MAJOR} in src/shared/CMakeLists.txt.
#     Those are reconciled by construction - that file reads the variables instead
#     of writing a number, so there is no second copy for this gate to compare.
#
# The header keeps checked-in literals rather than becoming a configure-time
# generated file: the include-boundary gate and the two self-containment gates
# grep include/sheller/ directly, and a header that only exists after a configure
# would make those scans find nothing and pass. So the literals stay, and this
# gate is what turns "must stay in sync" from a reminder into a mechanism.
#
# vcpkg.json's "version" is deliberately OUT OF SCOPE: it names this package
# inside vcpkg's manifest mode, and this project does not distribute itself
# through vcpkg (the manifest declares the four dependencies and nothing else).
# It is not a version claim made to a consumer of libsheller. If that changes, it
# belongs in this gate.
#
# Invoked as a ctest command (see tests/CMakeLists.txt):
#   -DGATE_ROOT=<project source dir>
#   -DPROJECT_VERSION=<x.y.z exactly as project() declares it>
#
# A missing macro, a missing literal, or a missing project() line is a hard error
# rather than a skip: a gate that goes green because it could not find what to
# compare is how a check goes silently blind.

foreach(required GATE_ROOT PROJECT_VERSION)
  if(NOT DEFINED "${required}" OR "${${required}}" STREQUAL "")
    message(FATAL_ERROR "version gate: -D${required} is required")
  endif()
endforeach()

set(version_header "${GATE_ROOT}/include/sheller/version.h")
set(project_file "${GATE_ROOT}/CMakeLists.txt")
foreach(must_exist version_header project_file)
  if(NOT EXISTS "${${must_exist}}")
    message(FATAL_ERROR "version gate: required file is gone: ${${must_exist}}")
  endif()
endforeach()

if(NOT PROJECT_VERSION MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
  message(FATAL_ERROR
    "version gate: project() version \"${PROJECT_VERSION}\" is not major.minor.patch. "
    "This gate compares the digits one at a time and will not guess at a shape.")
endif()

# ------------------------------------------------------------------- the ruler
# Reports "<label>:<line>" for the line a piece of text first starts on, so a
# failure names the place to edit rather than only the value that moved. The
# newline count over the prefix is the measure - file(STRINGS) cannot be used for
# this, because a source line containing a semicolon comes back as two list
# elements and shifts every number after it.
function(gate_line_of out blob needle label)
  string(FIND "${blob}" "${needle}" offset)
  if(offset LESS 0)
    message(FATAL_ERROR "version gate: ${needle} not found in ${label}")
  endif()
  string(SUBSTRING "${blob}" 0 "${offset}" prefix)
  string(REGEX MATCHALL "\n" newlines "${prefix}")
  list(LENGTH newlines preceding_newlines)
  math(EXPR line "${preceding_newlines} + 1")
  set(${out} "${label}:${line}" PARENT_SCOPE)
endfunction()

# Normalizes both files the same way: no carriage returns, and tabs become single
# spaces so the patterns below only have one form of horizontal whitespace to
# spell. The carriage-return strip is a general precaution rather than a fact
# about these two files, and it is worth being precise about that: .gitattributes
# pins the whole index to LF ("* text=auto eol=lf"), and git ls-files --eol
# reports include/sheller/version.h as "i/lf w/lf" - this header carries no CR at
# all. What the strip covers is the other direction: 26 files in this tree read
# "i/lf w/crlf", meaning a local tool flipped the working-tree copy while the index
# stayed LF. A gate that reads the working tree should not change its verdict
# depending on which of the two shapes it happened to get.
file(READ "${version_header}" header)
string(REPLACE "\r" "" header "${header}")
string(REPLACE "\t" " " header "${header}")

file(READ "${project_file}" project_text)
string(REPLACE "\r" "" project_text "${project_text}")
string(REPLACE "\t" " " project_text "${project_text}")

string(REGEX MATCH "project\\(sheller VERSION ([0-9]+)\\.([0-9]+)\\.([0-9]+)" _decl "${project_text}")
if(NOT _decl)
  message(FATAL_ERROR
    "version gate: CMakeLists.txt no longer declares \"project(sheller VERSION x.y.z)\". "
    "That is the one place the version is written down, so there is nothing left to "
    "reconcile against.")
endif()
set(decl_major "${CMAKE_MATCH_1}")
set(decl_minor "${CMAKE_MATCH_2}")
set(decl_patch "${CMAKE_MATCH_3}")
gate_line_of(decl_at "${project_text}" "project(sheller VERSION" "CMakeLists.txt")

# The value the build system was configured with has to be the value in the file.
# It is passed in from the generator's own variables, so a difference here means
# the build tree is stale relative to CMakeLists.txt - and a stale tree is a gate
# that quietly reconciles against a version nobody wrote down on purpose.
if(NOT PROJECT_VERSION STREQUAL "${decl_major}.${decl_minor}.${decl_patch}")
  message(FATAL_ERROR
    "version gate: the configured project version is ${PROJECT_VERSION} but "
    "${decl_at} declares ${decl_major}.${decl_minor}.${decl_patch}. Reconfigure - the "
    "library file name, the SONAME and the package version all come from the "
    "configured value, not from the file.")
endif()

foreach(position MAJOR MINOR PATCH)
  string(TOLOWER "${position}" position_lower)
  set(want "${decl_${position_lower}}")
  string(REGEX MATCH "#define SHELLER_VERSION_${position} +([0-9]+)" _found "${header}")
  if(NOT _found)
    message(FATAL_ERROR
      "version gate: include/sheller/version.h does not define "
      "SHELLER_VERSION_${position} as \"#define SHELLER_VERSION_${position} <number>\", "
      "so this gate has nothing to compare and refuses to pass.")
  endif()
  set(found "${CMAKE_MATCH_1}")
  if(NOT found STREQUAL want)
    gate_line_of(at "${header}" "#define SHELLER_VERSION_${position} " "include/sheller/version.h")
    message(FATAL_ERROR
      "version gate: the ${position_lower} version is written twice and disagrees.\n"
      "  ${at} defines SHELLER_VERSION_${position} ${found}\n"
      "  ${decl_at} declares project(sheller VERSION ${decl_major}.${decl_minor}.${decl_patch})\n"
      "Raise the header to the project version, or lower the project version - the two "
      "are one fact.")
  endif()
endforeach()

# The string a host can actually read at run time, which is not made of the three
# macros above and therefore drifts on its own.
#
# Read as "the first quoted string after version_string()", taken from a bounded
# window rather than a pattern: CMake's regex does not have a lazy quantifier, and
# a negated class meant to stop at the closing brace does not reliably do so. The
# window is long enough for the signature and the return statement and short
# enough that it cannot reach the comment below the function, which is exactly the
# text this first tried to read (it matched the "\"major.minor\"" in the unicorn
# version note) - a comment that happens to be the thing the gate captured is how
# a check passes for the wrong reason.
string(FIND "${header}" "version_string()" vs_offset)
if(vs_offset LESS 0)
  message(FATAL_ERROR
    "version gate: include/sheller/version.h has no version_string(), so there is no"
    " run-time version to reconcile.")
endif()
math(EXPR window_start "${vs_offset} + 16")
string(SUBSTRING "${header}" "${window_start}" 200 vs_window)
string(REGEX MATCH "\"([^\"]*)\"" _vs "${vs_window}")
if(NOT _vs)
  message(FATAL_ERROR
    "version gate: could not read the string literal version_string() returns in"
    " ${version_header}.")
endif()
set(literal "${CMAKE_MATCH_1}")
if(NOT literal MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
  message(FATAL_ERROR
    "version gate: the text read back from just after version_string() is"
    " \"${literal}\", which is not a version. The header's shape changed under this gate;"
    " it is not going to compare something else and call it a pass.")
endif()
if(NOT literal STREQUAL "${decl_major}.${decl_minor}.${decl_patch}")
  gate_line_of(literal_at "${header}" "version_string()" "include/sheller/version.h")
  message(FATAL_ERROR
    "version gate: the version a host can read disagrees with project().\n"
    "  ${literal_at} version_string() returns \"${literal}\"\n"
    "  ${decl_at} declares project(sheller VERSION ${decl_major}.${decl_minor}.${decl_patch})\n"
    "The SONAME and the package version both come from project(), so a consumer would "
    "be told one version by the loader and another by the library.")
endif()

message(STATUS
  "version gate: ${decl_major}.${decl_minor}.${decl_patch} reconciled - "
  "${decl_at}, three macros and the version_string() literal \"${literal}\" "
  "in ${version_header}")
