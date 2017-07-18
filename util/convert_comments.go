// Copyright (c) 2017, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"strings"
)

// convert_comments.go converts C-style block comments to C++-style line
// comments. A block comment is converted if all of the following are true:
//
//   * The comment begins after the first blank line, to leave the license
//     blocks alone.
//
//   * There are no characters between the '*/' and the end of the line.
//
//   * Either one of the following are true:
//
//     - The comment fits on one line.
//
//     - Each line the comment spans begins with N spaces, followed by '/*' for
//       the initial line or ' *' for subsequent lines, where N is the same for
//       each line.
//
// This tool is a heuristic. While it gets almost all cases correct, the final
// output should still be looked over and fixed up as needed.

// allSpaces returns true if |s| consists entirely of spaces.
func allSpaces(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r != ' ' }) == -1
}

// isContinuation returns true if |s| is a continuation line for a multi-line
// comment indented to the specified column.
func isContinuation(s string, column int) bool {
	if len(s) < column+2 {
		return false
	}
	if !allSpaces(s[:column]) {
		return false
	}
	return s[column:column+2] == " *"
}

// indexFrom behaves like strings.Index but only reports matches starting at
// |idx|.
func indexFrom(s, sep string, idx int) int {
	ret := strings.Index(s[idx:], sep)
	if ret < 0 {
		return -1
	}
	return idx + ret
}

// writeLine writes |line| to |out|, followed by a newline.
func writeLine(out *bytes.Buffer, line string) {
	out.WriteString(line)
	out.WriteByte('\n')
}

func convertComments(in []byte) []byte {
	lines := strings.Split(string(in), "\n")
	var out bytes.Buffer

	// Account for the trailing newline.
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}

	// Find the license block separator.
	for len(lines) > 0 {
		line := lines[0]
		lines = lines[1:]
		writeLine(&out, line)
		if len(line) == 0 {
			break
		}
	}

	// inComment is true if we are in the middle of a comment.
	var inComment bool
	// comment is the currently buffered multi-line comment to convert. If
	// |inComment| is true and it is nil, the current multi-line comment is
	// not convertable and we copy lines to |out| as-is.
	var comment []string
	// column is the column offset of |comment|.
	var column int
	for len(lines) > 0 {
		line := lines[0]
		lines = lines[1:]

		var idx int
		if inComment {
			// Stop buffering if this comment isn't eligible.
			if comment != nil && !isContinuation(line, column) {
				for _, l := range comment {
					writeLine(&out, l)
				}
				comment = nil
			}

			// Look for the end of the current comment.
			idx = strings.Index(line, "*/")
			if idx < 0 {
				if comment != nil {
					comment = append(comment, line)
				} else {
					writeLine(&out, line)
				}
				continue
			}

			inComment = false
			if comment != nil {
				if idx == len(line)-2 {
					// This is a convertable multi-line comment.
					if idx >= column+2 {
						// |idx| may be equal to
						// |column| + 1, if the line is
						// a '*/' on its own. In that
						// case, we discard the line.
						comment = append(comment, line[:idx])
					}
					for _, l := range comment {
						out.WriteString(l[:column])
						out.WriteString("//")
						writeLine(&out, strings.TrimRight(l[column+2:], " "))
					}
					comment = nil
					continue
				}

				// Flush the buffered comment unmodified.
				for _, l := range comment {
					writeLine(&out, l)
				}
				comment = nil
			}
			idx += 2
		}

		// Parse starting from |idx|, looking for either a convertable
		// line comment or a multi-line comment.
		for {
			idx = indexFrom(line, "/*", idx)
			if idx < 0 {
				writeLine(&out, line)
				break
			}

			endIdx := indexFrom(line, "*/", idx)
			if endIdx < 0 {
				inComment = true
				if allSpaces(line[:idx]) {
					// The comment is, so far, eligible for conversion.
					column = idx
					comment = []string{line}
				}
				break
			}

			if endIdx != len(line)-2 {
				// Continue parsing for more comments in this line.
				idx = endIdx + 2
				continue
			}

			out.WriteString(line[:idx])

			// Google C++ style prefers two spaces before a
			// comment if it is on the same line as code,
			// but clang-format has been placing one space
			// for block comments. Fix this.
			if !allSpaces(line[:idx]) {
				if line[idx-1] != ' ' {
					out.WriteString("  ")
				} else if line[idx-2] != ' ' {
					out.WriteString(" ")
				}
			}

			out.WriteString("//")
			writeLine(&out, strings.TrimRight(line[idx+2:endIdx], " "))
			break
		}
	}

	return out.Bytes()
}

func main() {
	for _, arg := range os.Args[1:] {
		in, err := ioutil.ReadFile(arg)
		if err != nil {
			panic(err)
		}
		if err := ioutil.WriteFile(arg, convertComments(in), 0666); err != nil {
			panic(err)
		}
	}
}
