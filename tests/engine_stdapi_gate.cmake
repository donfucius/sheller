# Engine throwing-standard-library-API gate: two families are hard-banned in an
# engine translation unit, because both throw and the engine carries no exception
# mechanism by its own rule (see tests/engine_nothrow_gate.cmake) - an escaping
# throw from here would be a library-internal error at the export face, when the
# engine already has a typed failure channel for it.
#
#   1. std::sto* (sto16/sto32/sto64/stof/stod/stold/stoul/stoull and friends):
#      throws std::invalid_argument or std::out_of_range on malformed or
#      out-of-range text. The channel for "the bytes did not parse" in this tree is
#      the typed failure the file already returns, or from_chars where a numeric
#      result is all that is wanted.
#   2. a filesystem operation called without its error_code overload: the throwing
#      form raises filesystem_error on the first permission, symlink or missing-path
#      surprise. Every such call in the tree takes the ec argument; this gate is what
#      keeps the next one from forgetting.
#
# No allowlist and no named exception: (1) has zero sites today and (2) is at zero
# violations today. A ban that ships with an exemption is a ban that starts eroding.
#
# INVOCATION (a ctest command, see tests/CMakeLists.txt):
#   -DGATE_ROOT=<project source dir>
#   -DGATE_SOURCE_LIST=<generated file: engine source paths, one per line>
#
# WHICH NAMES ARE OPERATIONS: the family is matched by shape - any
# filesystem::<name>( - and a short list of names is then declared not-an-operation
# (path and error constructors, the pure-string lexically_* helpers, the queries that
# take a file_status). Inverting it this way is the point: a name added by a future
# standard joins the banned set by default and the maintainer has to list it to
# release it, instead of a banned operation hiding because nobody thought to add it to
# a list. Measured against this tree that is the difference between 16 operations
# watched and 21 spelled out - relative(), weakly_canonical(), permissions(),
# is_other() and friends were simply absent from the old list, and a call to any of
# them was green without ever being counted.
#
# HOW THE ec TEST READS A CALL: the argument list has to be on the line that spells
# the operation, and the LAST argument has to be a name this file declared as a
# std::error_code. "Some comma appears in the arguments" is not the test -
# copy_file(src, dst) has a comma and throws. A wrapped call, nested parentheses
# inside the arguments, or an unreadable argument list at all is reported as a
# violation rather than skipped: an argument list the gate cannot read is treated as
# "no error_code", so reformatting can never turn a red gate green.

cmake_policy(SET CMP0057 NEW)
include("${CMAKE_CURRENT_LIST_DIR}/engine_gate_lines.cmake")

foreach(required GATE_ROOT GATE_SOURCE_LIST)
  if(NOT DEFINED "${required}" OR "${${required}}" STREQUAL "")
    message(FATAL_ERROR "engine_stdapi gate: -D${required} is required")
  endif()
endforeach()
if(NOT EXISTS "${GATE_SOURCE_LIST}")
  message(FATAL_ERROR
    "engine_stdapi gate: source list not found: ${GATE_SOURCE_LIST} (re-run the configure step)")
endif()

# ------------------------------------------------------------------ the patterns
# Same boundary spelling as the no-throw gate: CMake's \b is not a word boundary, so
# a negated class does the job. Word chars on both sides keep le::store_le16 and a
# comment about "storage" out of the set.
set(sto_pattern "(^|[^A-Za-z0-9_:])std::sto(i|ll|ull|ul|l|f|d|ld)([^A-Za-z0-9_]|$)")
# Names that are not operations: constructors, and the members of the library's
# non-throwing path/algebra corner. Anything absent from this list and reachable by
# the shape below is demanded an error_code.
set(fs_non_ops
  path u8path file_status perms filesystem_error directory_entry path_view
  hash_value status_known is_unknown to_u8 to_wide
  lexically_normal lexically_relative lexically_proximate)
# Any filesystem::<name>( call. The argument list is then read with string
# searches, NOT with a capture group: a pattern that has to match literal
# parentheses alongside a group is not something to hang a ban on. Measured on the
# toolchains, `(std::)?filesystem::(op)[ \t]*\(([^()]*)\)` reports two groups and
# hands the argument group back empty for a call that plainly has arguments - a
# "last argument" read out of that is empty, and an empty argument list is what
# decides whether the call is legal. So: find the operation, take the text after
# its opening paren, and walk to the closing one.
set(fs_call_pattern "(std::)?filesystem::([A-Za-z_][A-Za-z0-9_]*)[ \t]*\\(")
# A name declared in this file as the error slot of a call. Reference parameters
# included: std::error_code& ec is how a helper takes one.
set(fs_ec_decl "std::error_code[ \t*&]+([A-Za-z_][A-Za-z0-9_]*)")

file(STRINGS "${GATE_SOURCE_LIST}" sources_raw)
set(sources "")
foreach(line IN LISTS sources_raw)
  string(STRIP "${line}" entry)
  if(entry AND NOT entry MATCHES "^#")
    list(APPEND sources "${entry}")
  endif()
endforeach()
list(LENGTH sources source_count)
if(NOT source_count)
  message(FATAL_ERROR "engine_stdapi gate: ${GATE_SOURCE_LIST} lists no source file")
endif()

set(sto_hits 0)
set(fs_calls 0)
set(fs_missing_ec 0)
set(fs_non_op_calls 0)
set(violations "")

foreach(entry IN LISTS sources)
  set(path "${GATE_ROOT}/${entry}")
  if(NOT EXISTS "${path}")
    message(FATAL_ERROR "engine_stdapi gate: listed source does not exist: ${entry}")
  endif()
  file(READ "${path}" blob)
  string(REGEX REPLACE "\r" "" blob "${blob}")

  # Pass one: the names this file uses as error slots. A call is then judged
  # against the file it stands in, which is also what makes the test readable - no
  # second reading of the argument list can turn "ec" into something else.
  string(REGEX MATCHALL "${fs_ec_decl}" ec_matches "${blob}")
  set(ec_names "")
  foreach(found IN LISTS ec_matches)
    string(REGEX REPLACE "${fs_ec_decl}" "\\1" name "${found}")
    if(name AND NOT name IN_LIST ec_names)
      list(APPEND ec_names "${name}")
    endif()
  endforeach()

  set(number 0)
  set(walk TRUE)
  while(walk)
    gate_next_line("${blob}" line blob at_end)
    if(line STREQUAL "" AND at_end)
      break()
    endif()
    math(EXPR number "${number} + 1")

    if(line MATCHES "${sto_pattern}")
      math(EXPR sto_hits "${sto_hits} + 1")
      string(APPEND violations
        "\n  ${entry}:${number}: ${line}\n    (std::sto* throws; return the file's typed "
        "failure, or use from_chars)")
    endif()

    # Every filesystem operation has to end its argument list with an error slot this
    # file declared. The list is read with string searches, and anything the walk
    # cannot resolve - the arguments run off the line, or a nested call sits inside
    # them - is reported rather than skipped, so no spelling turns a red gate green.
    set(rest "${line}")
    set(scanning TRUE)
    while(scanning)
      if(NOT rest MATCHES "${fs_call_pattern}")
        set(scanning FALSE)
        break()
      endif()
      set(op_name "${CMAKE_MATCH_2}")
      # The match is located, not assumed to start at the front of the remaining
      # text: a call inside an `if (...)` has everything before the paren that does
      # not belong to its arguments.
      set(head "${CMAKE_MATCH_0}")
      string(FIND "${rest}" "${head}" head_at)
      string(LENGTH "${head}" head_length)
      math(EXPR tail_at "${head_at} + ${head_length}")
      string(SUBSTRING "${rest}" "${tail_at}" -1 tail)
      string(FIND "${tail}" ")" close)
      string(FIND "${tail}" "(" nested)
      set(args "")
      set(readable TRUE)
      if(close LESS 0)
        set(readable FALSE)
      elseif(NOT nested LESS 0 AND nested LESS close)
        set(readable FALSE)
      else()
        string(SUBSTRING "${tail}" 0 "${close}" args)
      endif()
      if(op_name IN_LIST fs_non_ops)
        math(EXPR fs_non_op_calls "${fs_non_op_calls} + 1")
      elseif(NOT readable)
        math(EXPR fs_missing_ec "${fs_missing_ec} + 1")
        string(APPEND violations
          "\n  ${entry}:${number}: ${line}\n    (the gate cannot read this filesystem "
          "call's argument list - a wrapped call or nested parentheses - and an unreadable "
          "error_code is treated as missing, not as absent)")
      else()
        math(EXPR fs_calls "${fs_calls} + 1")
        string(REGEX REPLACE "^.*," "" last_arg "${args}")
        string(STRIP "${last_arg}" last_arg)
        # An empty argument list is spelled out rather than left to the membership
        # test: `"" IN_LIST <names>` does not read as false in every cmake version,
        # and a no-argument throwing call is exactly the case that must not pass.
        if(args STREQUAL "" OR NOT last_arg IN_LIST ec_names)
          math(EXPR fs_missing_ec "${fs_missing_ec} + 1")
          string(APPEND violations
            "\n  ${entry}:${number}: ${line}\n    (filesystem operation \"${op_name}\" whose "
            "last argument is not an error_code declared in this file - the throwing form "
            "raises filesystem_error; take the ec overload and route the error through this "
            "file's existing failure channel)")
        endif()
      endif()
      math(EXPR step "${tail_at} + 1")
      string(LENGTH "${rest}" rest_length)
      # The advance is bounded, not assumed: a call that runs to the end of the line
      # (the usual shape of a wrapped argument list, and the case that must be
      # reported) leaves no text behind, and SUBSTRING past the last character is a
      # script error rather than a finding - it would fail the gate with a message
      # that names nothing instead of naming the file and the line.
      if(step GREATER_EQUAL rest_length)
        set(scanning FALSE)
      else()
        string(SUBSTRING "${rest}" "${step}" -1 rest)
      endif()
    endwhile()
  endwhile()
endforeach()

if(violations)
  message(FATAL_ERROR
    "engine_stdapi gate: throwing standard-library API in the engine sources "
    "(std::sto* hits: ${sto_hits}, filesystem operations without an error_code: "
    "${fs_missing_ec}):${violations}")
endif()

message(STATUS
  "engine_stdapi gate: ${source_count} engine source file(s) scanned - "
  "${sto_hits} std::sto* hit(s), ${fs_calls} filesystem operation(s) all ending in an "
  "error_code declared in the file, ${fs_non_op_calls} non-operation filesystem name(s) "
  "(constructors and the non-throwing path algebra)")
