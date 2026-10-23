# Engine standard-stream gate: an engine translation unit must not write the
# host's stdout or stderr. The library is embedded in somebody else's process;
# bytes it sends to a standard stream land in that host's console, mixed with its
# own output, and cannot be recalled. Everything the engine has to say goes
# through the log facade instead, which the host can install, filter, or silence.
#
# The pattern set is a family of spellings, not a set of substrings:
#   fprintf_stderr   fprintf ( ... stderr         - the diagnostic spelling
#   bare_printf      printf(                     - anchored, so that neither
#                                                  "snprintf(" nor "fprintf("
#                                                  reads as a bare printf
#   fputs / fwrite / puts                        - the C stream writers
#   std_streams      std::cerr / std::cout / std::clog
#   open_call        fprintf( <end of line>      - a call whose stream argument is
#                                                  on the next line; run.cpp's leg
#                                                  trace is spelled that way. Any
#                                                  stream it opens is a host stream,
#                                                  so counting the opener is the
#                                                  fail-closed direction
# snprintf is not a hit: it fills a buffer and writes no stream, and the engine
# has two legitimate calls (a C++ handler name, a wrapper file name). A rule keyed
# on the substring printf( would flag every fprintf site and both of those.
#
# Comments are stripped before matching, "//" and "/* */" alike: these files
# discuss their own diagnostics constantly, and prose about a write is not a
# write. The stripper is textual rather than a lexer - a "//" inside a string
# literal ends that line's code early, which loses coverage instead of inventing a
# finding.
#
# The allowlist is the ratchet. One entry per registered site, as
#   <path><TAB><needle><TAB><count>
# with needle a substring of the site's own line (so it names the call, not the
# file) and count the number of statements that needle must claim. A hit is offered
# to the entries of its own file in order of decreasing needle length - most
# specific first, and only that one entry claims it - because a short opener is by
# construction a substring of the statements it opens. Three failures, each reported
# by name:
#   a hit no entry of its file matches  - a new spelling writing to a host stream
#   an entry claiming more than its count - a registered spelling that gained a
#                                          second statement
#   an entry claiming fewer, zero included - a stale entry: the site has been
#                                           rerouted or deleted, and the exception
#                                           it granted goes with it
# The list can therefore only shrink, and a finished reroute leaves no dead entry
# behind. Reaching zero is the goal; the empty file stays, so that "register your
# site" remains an action somebody has to take and see.
#
# INVOCATION (a ctest command, see tests/CMakeLists.txt):
#   -DGATE_ROOT=<project source dir>
#   -DGATE_SOURCE_LIST=<generated file: engine source paths, one per line>
#   -DGATE_ALLOWLIST=<checked-in allowlist>

cmake_policy(SET CMP0057 NEW)
include("${CMAKE_CURRENT_LIST_DIR}/engine_gate_lines.cmake")

foreach(required GATE_ROOT GATE_SOURCE_LIST GATE_ALLOWLIST)
  if(NOT DEFINED "${required}" OR "${${required}}" STREQUAL "")
    message(FATAL_ERROR "engine_stdstream gate: -D${required} is required")
  endif()
endforeach()
foreach(must_exist GATE_SOURCE_LIST GATE_ALLOWLIST)
  if(NOT EXISTS "${${must_exist}}")
    message(FATAL_ERROR
      "engine_stdstream gate: ${must_exist} not found: ${${must_exist}} "
      "(re-run the configure step)")
  endif()
endforeach()

# Lines are scanned with a space prepended, so the anchor class always has a
# character to look at even for a call written at column zero.
#
# The families are wider than the spellings this tree happened to contain when the
# gate was written, and the last one wider still: the identifiers stdout and stderr
# are named at all. That closes the alias route - bind a stream to a variable, or
# reach for the wide-character or vector forms, and the code still has to spell one
# of these two words or one of these writer names. Measured on this tree, stdout and
# stderr appear on zero code lines (three comments discuss them, and comments are
# stripped before matching), so naming them costs nothing today and stops the rule
# being a list of the shapes somebody thought of first.
set(pattern_ids
  fprintf_stderr printf_family write_family puts std_streams freopen host_stream_token open_call)
# A stream passed as the first argument of a printf family call: the spelling that
# was the whole problem before the traces moved to the log facade.
set(fprintf_stderr_pattern
  "[^A-Za-z0-9_][fvw]*printf[ \t]*\\([ \t]*(std::)?(stderr|stdout)")
# printf, fprintf, vprintf, vfprintf, wprintf, fwprintf. sprintf is deliberately
# out - it fills a buffer - and it stays out because the character before "printf"
# there is a word character, which is the same test that keeps snprintf out.
set(printf_family_pattern "[^A-Za-z0-9_.][fvw]*printf[ \t]*\\(")
set(write_family_pattern
  "[^A-Za-z0-9_.](fputs|fputws|fputwc|fputc|putwc|putc|putchar|fwrite)[ \t]*\\(")
set(puts_pattern "[^A-Za-z0-9_.]puts[ \t]*\\(")
set(std_streams_pattern "std::w?c(err|out|log)")
# freopen repoints a standard stream at a file; that is the same act, described
# differently.
set(freopen_pattern "[^A-Za-z0-9_.]freopen[ \t]*\\(")
set(host_stream_token_pattern "(^|[^A-Za-z0-9_])(stdout|stderr)([^A-Za-z0-9_]|$)")
set(open_call_pattern
  "[^A-Za-z0-9_.]([fvw]*printf|fputs|fputws|fputwc|fputc|putwc|putc|putchar|fwrite|freopen|puts)[ \t]*\\([ \t]*$")

# ---------------------------------------------------------------- the allowlist
# Read with the same walker as the sources, not file(STRINGS): a needle is cut
# from a call's own text, so it routinely ends in a comma - and file(STRINGS)
# merges a line that ends with one into the next (the measurement behind
# engine_gate_lines.cmake). One entry per iteration, accumulated into parallel
# lists that hold only our own text.
file(READ "${GATE_ALLOWLIST}" allowlist_blob)
string(REGEX REPLACE "\r" "" allowlist_blob "${allowlist_blob}")
set(entry_count 0)
set(entry_walk TRUE)
while(entry_walk)
  gate_next_line("${allowlist_blob}" allowline allowlist_blob entry_end)
  if(allowline STREQUAL "" AND entry_end)
    break()
  endif()
  string(STRIP "${allowline}" entry)
  if(entry STREQUAL "" OR entry MATCHES "^#")
    continue()
  endif()
  # Split on the two tabs by position. The fields are never put through a CMake
  # list: a needle carries quotes and semicolons from the source line it names,
  # and list parsing of such a value merges elements (measured) - which is the
  # same effect that makes file(STRINGS) unusable for source.
  string(FIND "${entry}" "	" first_tab)
  if(first_tab LESS 0)
    message(FATAL_ERROR
      "engine_stdstream gate: an entry has no tab: ${entry}")
  endif()
  string(SUBSTRING "${entry}" 0 "${first_tab}" path_field)
  math(EXPR after_first "${first_tab} + 1")
  string(SUBSTRING "${entry}" "${after_first}" -1 tail)
  string(FIND "${tail}" "	" second_tab)
  if(second_tab LESS 0)
    message(FATAL_ERROR
      "engine_stdstream gate: an entry is not <path><TAB><needle><TAB><count>: ${entry}")
  endif()
  string(SUBSTRING "${tail}" 0 "${second_tab}" needle)
  math(EXPR after_second "${second_tab} + 1")
  string(SUBSTRING "${tail}" "${after_second}" -1 count_field)
  string(STRIP "${count_field}" count_field)
  if(NOT count_field MATCHES "^[0-9]+$")
    message(FATAL_ERROR "engine_stdstream gate: count is not a number: ${entry}")
  endif()
  set(entry_path_${entry_count} "${path_field}")
  set(entry_needle_${entry_count} "${needle}")
  set(entry_count_${entry_count} "${count_field}")
  set(entry_tally_${entry_count} 0)
  math(EXPR entry_count "${entry_count} + 1")
endwhile()

# Claim order: the longest needle of a file is offered a hit first. Selection sort
# over entry indices - the items are integers, so this one list is safe to build
# with list() (the entries themselves are not; see the split above). Ties keep the
# earlier declaration, which makes the order reproducible from the file.
#
# Why the order matters: the entry that names a call written across two lines can
# only carry the opener the first line leaves behind ("std::fprintf(stderr,") - and
# that is a substring of every whole statement in the same file. Offered in
# declaration order such an opener takes a site a narrow needle was written for,
# and the narrow entry then reads as stale while the wrapped site comes up
# uncovered. Most-specific-first gives each site to the entry that actually names
# it, whatever order the two are declared in.
set(claim_order "")
set(picked 0)
while(picked LESS entry_count)
  set(best -1)
  set(best_length -1)
  set(position 0)
  while(position LESS entry_count)
    list(FIND claim_order "${position}" already_ordered)
    if(already_ordered LESS 0)
      string(LENGTH "${entry_needle_${position}}" needle_length)
      if(needle_length GREATER best_length)
        set(best "${position}")
        set(best_length "${needle_length}")
      endif()
    endif()
    math(EXPR position "${position} + 1")
  endwhile()
  list(APPEND claim_order "${best}")
  math(EXPR picked "${picked} + 1")
endwhile()

# -------------------------------------------------------------------- the scan
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
  message(FATAL_ERROR "engine_stdstream gate: ${GATE_SOURCE_LIST} lists no source file")
endif()

if(GATE_SITE_DUMP)
  file(WRITE "${GATE_SITE_DUMP}" "")
endif()

# A hit is claimed where it is found, so no source text ever has to be stored in
# a list - source code is made of CMake's list separator.
set(hit_count 0)
set(uncovered "")
foreach(entry IN LISTS sources)
  set(path "${GATE_ROOT}/${entry}")
  if(NOT EXISTS "${path}")
    message(FATAL_ERROR "engine_stdstream gate: listed source does not exist: ${entry}")
  endif()
  file(READ "${path}" blob)
  string(REGEX REPLACE "\r" "" blob "${blob}")
  set(in_block FALSE)
  set(shown 0)
  set(walk TRUE)
  while(walk)
    gate_next_line("${blob}" raw blob at_end)
    if(raw STREQUAL "" AND at_end)
      break()
    endif()
    math(EXPR shown "${shown} + 1")
    gate_strip_comments("${raw}" "${in_block}" code in_block)
    if(code STREQUAL "")
      continue()
    endif()
    set(scanned " ${code}")
    set(matched_id "")
    foreach(id IN LISTS pattern_ids)
      set(pattern "${${id}_pattern}")
      if(scanned MATCHES "${pattern}")
        set(matched_id "${id}")
        break()
      endif()
    endforeach()
    if(matched_id STREQUAL "")
      continue()
    endif()
    math(EXPR hit_count "${hit_count} + 1")
    set(claimed FALSE)
    foreach(position IN LISTS claim_order)
      if(entry_path_${position} STREQUAL entry)
        # No cap: the first entry that matches, in that most-specific-first order,
        # is the claimer, and its tally is compared against its registered count
        # afterwards. Capping here would make an entry unable to outgrow its number
        # - growth would then surface as "not covered by any entry", which sends the
        # maintainer to the wrong row of the table.
        string(FIND "${scanned}" "${entry_needle_${position}}" at)
        if(at GREATER -1)
          set(claimed TRUE)
          math(EXPR entry_tally_${position} "${entry_tally_${position}} + 1")
          break()
        endif()
      endif()
    endforeach()
    if(NOT claimed)
      string(APPEND uncovered "\n    ${entry}:${shown}  [${matched_id}] ${code}")
    endif()
    # Machine-readable inventory of what the scan saw, for whoever maintains the
    # allowlist (-DGATE_SITE_DUMP=<path>; one site per line, tab-separated, the
    # pattern that fired and the line number). The failure report below is for a
    # human and CMake's message formatter wraps it mid-site, so a table regenerated
    # from the tree has to read this dump rather than the report.
    if(GATE_SITE_DUMP)
      # The text goes out verbatim: the allowlist needle is cut from it, and a
      # needle has to match the scanned line character for character, so
      # collapsing the indentation here would invent a needle that never matches.
      file(APPEND "${GATE_SITE_DUMP}" "${entry}\t${matched_id}\t${shown}\t${code}\n")
    endif()
  endwhile()
endforeach()

# ------------------------------------------------------------- the verdict set
set(mismatched "")
set(position 0)
while(position LESS entry_count)
  set(path_field "${entry_path_${position}}")
  set(needle "${entry_needle_${position}}")
  set(registered "${entry_count_${position}}")
  set(tally "${entry_tally_${position}}")
  if(NOT tally STREQUAL registered)
    if(tally GREATER registered)
      set(kind "grew past its registered count - the ratchet only goes down")
    elseif(tally EQUAL 0)
      # One string, not two: set() with two arguments builds a list, and the list
      # separator would print as a semicolon in the middle of this sentence.
      set(kind "matches nothing - the site it registered has been rerouted or deleted, so remove the entry")
    else()
      set(kind "matches fewer sites than registered - tighten the number")
    endif()
    string(APPEND mismatched
      "\n    ${path_field}: needle <${needle}> registered ${registered}, actual "
      "${tally} - ${kind}")
  endif()
  math(EXPR position "${position} + 1")
endwhile()

if(uncovered OR mismatched)
  set(report "engine_stdstream gate: the host-standard-stream ratchet is broken")
  string(APPEND report
    " (${hit_count} write site(s) found, ${entry_count} allowlist entry(ies))")
  if(uncovered)
    string(APPEND report
      "\n  Not covered by any allowlist entry - the library must not write a host"
      "\n  standard stream; send it through log::write() instead, which the host can"
      "\n  install, filter and silence:${uncovered}")
  endif()
  if(mismatched)
    string(APPEND report "\n  Allowlist entries out of agreement with the tree:${mismatched}")
  endif()
  message(FATAL_ERROR "${report}")
endif()


message(STATUS
  "engine_stdstream gate: ${source_count} engine source file(s) scanned, ${hit_count} "
  "write site(s) covered by ${entry_count} allowlist entry(ies)")
