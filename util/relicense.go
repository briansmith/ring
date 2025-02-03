// Copyright 2025 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build ignore

// relicense.go rewrites the license headers of the files it is passed in. It is
// intended to be run as:
//
//	git ls-tree -r --name-only HEAD | xargs go run ./util/relicense.go
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

type commentStyle int

const (
	commentStyleC commentStyle = iota
	commentStyleHash
)

func lineComment(style commentStyle) string {
	switch style {
	case commentStyleC:
		return "//"
	case commentStyleHash:
		return "#"
	}
	panic("unknown comment type")
}

func commentBlockLength(style commentStyle, lines []string) int {
	if len(lines) == 0 {
		return 0
	}

	if style == commentStyleC && strings.HasPrefix(lines[0], "/*") {
		if idx := strings.Index(lines[0][2:], "*/"); idx >= 0 {
			idx += 2
			if idx+2 != len(lines[0]) {
				// The comment does not reach the end of the line.
				return 0
			}
			return 1
		}
		for i := 1; i < len(lines); i++ {
			if idx := strings.Index(lines[i], "*/"); idx >= 0 {
				if idx+2 != len(lines[i]) {
					// The comment does not reach the end of the line.
					return 0
				}
				return i + 1
			}
		}
		// Could not find the end of the comment
		return 0
	}

	// Treat consecutive line comments as
	prefix := lineComment(style)
	l := 0
	for l < len(lines) && strings.HasPrefix(lines[l], prefix) {
		l++
		// Some of our Perl files do not include a blank line at the end of the
		// license notice. Treat that as ending the comment block.
		if strings.HasPrefix(lines[l-1], "# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE") {
			break
		}
		if strings.HasPrefix(lines[l-1], "# https://www.openssl.org/source/license.html") {
			break
		}
		if strings.HasPrefix(lines[l-1], "# found in the LICENSE file.") {
			break
		}
	}
	return l
}

func commentStyleForPath(path string) (commentStyle, error) {
	for _, suffix := range []string{".c", ".cc", ".h", ".cc.inc", ".go", ".S", ".rs"} {
		if strings.HasSuffix(path, suffix) {
			return commentStyleC, nil
		}
	}
	for _, suffix := range []string{".pl", ".py", ".peg", ".bazel", ".bzl", "/BUILD.toplevel", "/WORKSPACE.toplevel", ".txt", "/DEPS", ".cmake", ".sh", ".bazelrc", ".toml"} {
		if strings.HasSuffix(path, suffix) {
			return commentStyleHash, nil
		}
	}
	return 0, errors.New("unknown comment style")
}

var licenseRegexp = regexp.MustCompile(`(?i)\b(copyright|authors?|licen[cs]e[ds]?|permission|warranty|warranties)\b`)

func findLicenseKeyword(lines []string) (string, bool) {
	for _, line := range lines {
		m := licenseRegexp.FindString(line)
		if len(m) != 0 {
			return m, true
		}
	}
	return "", false
}

func process(path string) error {
	inp, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// If the file does not currently have any license or copyright text,
	// ignore it.
	lines := strings.Split(string(inp), "\n")
	if _, ok := findLicenseKeyword(lines); !ok {
		return nil
	}

	// Clear a bunch of false positives so the remainder can be looked at by
	// hand.

	// gen files are generated and third_party should remain untouched.
	if strings.HasPrefix(path, "gen/") || strings.HasPrefix(path, "third_party/") {
		return nil
	}
	// Fuzzer corpora sometimes contain stray strings.
	if strings.HasPrefix(path, "fuzz/") && strings.Contains(path, "_corpus") {
		return nil
	}
	// These files do not have license headers but are false positives.
	if slices.Contains([]string{"AUTHORS", "CONTRIBUTING.md", "LICENSE", "MODULE.bazel.lock"}, path) {
		return nil
	}

	style, err := commentStyleForPath(path)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	// Copy over the #! line in perlasm files.
	if style == commentStyleHash && len(lines) > 0 && strings.HasPrefix(lines[0], "#!") {
		fmt.Fprintf(&b, "%s\n", lines[0])
		lines = lines[1:]
	}
	// Copy over the coding= line in Python files.
	if style == commentStyleHash && len(lines) > 0 && strings.HasPrefix(lines[0], "# coding=") {
		fmt.Fprintf(&b, "%s\n", lines[0])
		lines = lines[1:]
	}
	// Sometimes there is a blank line before the license.
	if len(lines) > 0 && len(lines[0]) == 0 {
		fmt.Fprintf(&b, "%s\n", lines[0])
		lines = lines[1:]
	}

	// Look for the existing license header.
	n := commentBlockLength(style, lines)
	if n == 0 {
		return errors.New("could not find comment block")
	}
	comment, lines := lines[:n], lines[n:]

	// Trim comment markers from comment lines.
	for i := range comment {
		comment[i] = strings.TrimPrefix(comment[i], lineComment(style))
		comment[i] = strings.TrimPrefix(comment[i], "/*")
		comment[i] = strings.TrimSuffix(comment[i], "*/")
		comment[i] = strings.TrimPrefix(comment[i], " *")
		comment[i] = strings.TrimSpace(comment[i])
	}

	// Remove leading and trailing whitespace.
	for len(comment) > 0 && len(comment[0]) == 0 {
		comment = comment[1:]
	}
	for len(comment) > 0 && len(comment[len(comment)-1]) == 0 {
		comment = comment[:len(comment)-1]
	}

	// Collect copyright lines.
	for n = 0; n < len(comment) && (strings.HasPrefix(comment[n], "Copyright ") || strings.HasPrefix(comment[n], "Author:")); n++ {
	}
	copyright, comment := comment[:n], comment[n:]
	if len(copyright) == 0 {
		return errors.New("could not find copyright notices")
	}

	// Leave support code alone for now.
	if strings.HasPrefix(path, "ssl/test/runner/") && strings.HasSuffix(copyright[0], "The Go Authors. All rights reserved.") {
		return nil
	}
	if strings.HasPrefix(path, "util/bot/") && strings.HasSuffix(copyright[0], "The Chromium Authors. All rights reserved.") {
		return nil
	}

	// The remainder must be one of the expected licenses.
	license := strings.Join(comment, "\n")
	if !slices.Contains(allowedLicenses, license) {
		const maxLicenseBlock = 25
		trunc := license
		if len(trunc) > maxLicenseBlock {
			trunc = trunc[:maxLicenseBlock] + "..."
		}
		return fmt.Errorf("license block %q unexpected", trunc)
	}

	// Assemble the new file contents.
	for _, line := range copyright {
		fmt.Fprintf(&b, "%s %s\n", lineComment(style), line)
	}
	for _, line := range strings.Split(apacheFileHeader, "\n") {
		if len(line) == 0 {
			fmt.Fprintf(&b, "%s\n", lineComment(style))
		} else {
			fmt.Fprintf(&b, "%s %s\n", lineComment(style), line)
		}
	}
	b.WriteString(strings.Join(lines, "\n"))

	if err := os.WriteFile(path, b.Bytes(), 0666); err != nil {
		return err
	}

	// If any text after the header contains license keywords, warn that we need
	// to check it by hand.
	if keyword, ok := findLicenseKeyword(lines); ok {
		return fmt.Errorf("file body contains %q, double-check by hand", keyword)
	}

	return nil
}

func main() {
	for _, path := range os.Args[1:] {
		if err := process(path); err != nil {
			fmt.Fprintf(os.Stderr, "Error processing %q: %s\n", path, err)
		}
	}
}

var allowedLicenses = []string{
	`
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.`,
	`
Licensed under the OpenSSL license (the "License").  You may not use
this file except in compliance with the License.  You can obtain a copy
in the file LICENSE in the source distribution or at
https://www.openssl.org/source/license.html`,
	`Use of this source code is governed by a BSD-style
license that can be found in the LICENSE file.`,
	`Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.`,
}

const apacheFileHeader = `
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.`
