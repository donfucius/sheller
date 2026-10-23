# Shared scanning primitives for the engine discipline gates
# (tests/engine_nothrow_gate.cmake, engine_stdapi_gate.cmake,
#  engine_at_ratchet_gate.cmake, engine_stdstream_gate.cmake).
#
# WHY THERE IS NO "READ A FILE INTO A LIST OF LINES" HELPER HERE.
# It is what every gate wants, and it does not work in CMake. Measured on
# src/engine/engine_hooks.cpp (929 physical lines): a loop that splits
# file(READ)'s contents at each '\n' visits all 929 lines, but 11 of them do not
# extend the list they are APPENDed to - they merge into their neighbour. Four
# storage schemes were tried (raw, ';' escaped, ';' and '\' escaped, trailing
# space, marker prefix) and every one of them ended at 918 elements. Without the
# escapes the same list inflates to 1332 instead, because ';' is CMake's list
# separator and almost every statement ends with one. A list of source lines is
# therefore either losing lines or inventing them, depending on the escaping -
# and a gate whose line numbers drift also counts its statements wrong.
#
# So the gates walk the file themselves: one line off the front of a blob per
# step, held in a plain variable that is never appended to anything. That walk is
# exact (929 iterations, measured). What accumulates is counters, and report text
# with its semicolons replaced for display. gate_next_line below is the whole
# trick; the caller keeps the line number, which is the point of doing it.

# Take the next physical line off the front of a blob. Outputs the line ("" once
# the blob is spent), the remainder, and at_end. Carriage returns are dropped by
# the caller once, over the whole contents, so a CRLF file and an LF file scan
# identically.
function(gate_next_line blob out_line out_rest out_at_end)
  string(LENGTH "${blob}" length)
  if(length EQUAL 0)
    set(${out_line} "" PARENT_SCOPE)
    set(${out_rest} "" PARENT_SCOPE)
    set(${out_at_end} TRUE PARENT_SCOPE)
    return()
  endif()
  string(FIND "${blob}" "\n" newline)
  if(newline EQUAL -1)
    set(${out_line} "${blob}" PARENT_SCOPE)
    set(${out_rest} "" PARENT_SCOPE)
    set(${out_at_end} TRUE PARENT_SCOPE)
    return()
  endif()
  string(SUBSTRING "${blob}" 0 "${newline}" one)
  math(EXPR skip "${newline} + 1")
  string(SUBSTRING "${blob}" "${skip}" -1 rest)
  set(${out_line} "${one}" PARENT_SCOPE)
  set(${out_rest} "${rest}" PARENT_SCOPE)
  set(${out_at_end} FALSE PARENT_SCOPE)
endfunction()

# Drop the comment text from one physical line. in_block says whether a block
# comment was open when the line started; the output carries that state forward.
# Line comments ("//") and block comments ("/* */") both go, so prose about a
# diagnostic is not read as one. The stripper is textual, not a lexer: a "//"
# inside a string literal ends that line's code early, which loses coverage
# rather than inventing a finding.
function(gate_strip_comments line was_in_block out_code out_in_block)
  set(text "${line}")
  set(in_block "${was_in_block}")
  set(code "")
  # A defined variable, not the constant TRUE: on the Linux side of the dual-platform
  # loop the gates run under cmake 3.25 in script mode, where no cmake_minimum_required
  # has set CMP0012, and `while(TRUE)` then reads TRUE as a *variable name* - undefined,
  # so the body never runs and every line comes back with its code stripped away
  # (measured: 0 of 17118 lines kept any code, so the gate reported 0 write sites and
  # called all 25 allowlist entries stale). cmake 4.4 on Windows reads the same line as
  # a true constant and the gate finds 26. A variable holding "TRUE" is true on both.
  set(scanning TRUE)
  while(scanning)
    if(in_block)
      string(FIND "${text}" "*/" close)
      if(close EQUAL -1)
        set(text "")
        break()
      endif()
      math(EXPR after "${close} + 2")
      string(SUBSTRING "${text}" "${after}" -1 text)
      set(in_block FALSE)
    endif()
    string(FIND "${text}" "//" slash)
    string(FIND "${text}" "/*" star)
    set(comment_start -1)
    set(comment_is_block FALSE)
    if(NOT slash EQUAL -1 AND (star EQUAL -1 OR star GREATER slash))
      set(comment_start "${slash}")
    elseif(NOT star EQUAL -1)
      set(comment_start "${star}")
      set(comment_is_block TRUE)
    endif()
    if(comment_start EQUAL -1)
      string(APPEND code "${text}")
      break()
    endif()
    string(SUBSTRING "${text}" 0 "${comment_start}" head)
    string(APPEND code "${head}")
    if(comment_is_block)
      math(EXPR after "${comment_start} + 2")
      string(SUBSTRING "${text}" "${after}" -1 text)
      set(in_block TRUE)
    else()
      break()
    endif()
  endwhile()
  set(${out_code} "${code}" PARENT_SCOPE)
  set(${out_in_block} "${in_block}" PARENT_SCOPE)
endfunction()
