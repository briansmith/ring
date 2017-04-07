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
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// delocate performs several transformations of textual assembly code. See
// FIPS.md in this directory for an overview.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

func main() {
	// The .a file, if given, is expected to be an archive of textual
	// assembly sources. That's odd, but CMake really wants to create
	// archive files so it's the only way that we can make it work.
	arInput := flag.String("a", "", "Path to a .a file containing assembly sources")

	outFile := flag.String("o", "", "Path to output assembly")
	asmFiles := flag.String("as", "", "Comma separated list of assembly inputs")

	flag.Parse()

	var lines []string
	var err error
	if len(*arInput) > 0 {
		if lines, err = arLines(lines, *arInput); err != nil {
			panic(err)
		}
	}

	asPaths := strings.Split(*asmFiles, ",")
	for i, path := range asPaths {
		if lines, err = asLines(lines, path, i); err != nil {
			panic(err)
		}
	}

	symbols := definedSymbols(lines)
	lines = transform(lines, symbols)

	out, err := os.OpenFile(*outFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	for _, line := range lines {
		out.WriteString(line)
		out.WriteString("\n")
	}
}

// isSymbolDef returns detects whether line contains a (non-local) symbol
// definition. If so, it returns the symbol and true. Otherwise it returns ""
// and false.
func isSymbolDef(line string) (string, bool) {
	line = strings.TrimSpace(line)

	if len(line) > 0 && line[len(line)-1] == ':' && line[0] != '.' {
		symbol := line[:len(line)-1]
		if validSymbolName(symbol) {
			return symbol, true
		}
	}

	return "", false
}

// definedSymbols finds all (non-local) symbols from lines and returns a map
// from symbol name to whether or not that symbol is global.
func definedSymbols(lines []string) map[string]bool {
	globalSymbols := make(map[string]struct{})
	symbols := make(map[string]bool)

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		if symbol, ok := isSymbolDef(line); ok {
			_, isGlobal := globalSymbols[symbol]
			symbols[symbol] = isGlobal
		}

		parts := strings.Fields(strings.TrimSpace(line))
		if parts[0] == ".globl" {
			globalSymbols[parts[1]] = struct{}{}
		}
	}

	return symbols
}

// transform performs a number of transformations on the given assembly code.
// See FIPS.md in the current directory for an overview.
func transform(lines []string, symbols map[string]bool) (ret []string) {
	ret = append(ret, ".text", "BORINGSSL_bcm_text_start:")

	// redirectors maps from out-call symbol name to the name of a
	// redirector function for that symbol.
	redirectors := make(map[string]string)

	// ia32capAddrNeeded is true iff OPENSSL_ia32cap_addr has been
	// referenced and thus needs to be emitted outside the module.
	ia32capAddrNeeded := false

	// extractedText contains lines that have been extracted from the
	// assembly and need to be moved outside of the module. (This is used
	// for the .init_array section that specifies constructors.)
	var extractedText []string
	extractingText := false

	// bssAccessorsNeeded contains the names of BSS symbols for which
	// accessor functions need to be emitted outside of the module.
	var bssAccessorsNeeded []string

	for lineNo, line := range lines {
		if strings.Contains(line, "OPENSSL_ia32cap_P(%rip)") {
			panic("reference to OPENSSL_ia32cap_P needs to be changed to indirect via OPENSSL_ia32cap_addr")
		}

		if strings.Contains(line, "OPENSSL_ia32cap_addr(%rip)") {
			ia32capAddrNeeded = true
		}

		parts := strings.Fields(strings.TrimSpace(line))

		if len(parts) == 0 {
			ret = append(ret, line)
			continue
		}

		switch parts[0] {
		case "call", "callq", "jmp":
			target := parts[1]
			// indirect via register or local label
			if strings.HasPrefix(target, "*") || strings.HasPrefix(target, ".L") {
				ret = append(ret, line)
				continue
			}

			if isGlobal, ok := symbols[target]; ok {
				newTarget := target
				if isGlobal {
					newTarget = localTargetName(target)
				}
				ret = append(ret, fmt.Sprintf("\t%s %s", parts[0], newTarget))
				continue
			}

			redirectorName := "bcm_redirector_" + target

			if strings.HasSuffix(target, "@PLT") {
				withoutPLT := target[:len(target)-4]
				if isGlobal, ok := symbols[withoutPLT]; ok {
					newTarget := withoutPLT
					if isGlobal {
						newTarget = localTargetName(withoutPLT)
					}
					ret = append(ret, fmt.Sprintf("\t%s %s", parts[0], newTarget))
					continue
				}

				redirectorName = redirectorName[:len(redirectorName)-4]
			}

			ret = append(ret, fmt.Sprintf("\t%s %s", parts[0], redirectorName))
			redirectors[redirectorName] = target
			continue

		case ".file":
			// Do not reorder .file directives. These define
			// numbered files which are referenced by other debug
			// directives which may not be reordered.
			ret = append(ret, line)
			continue

		case ".comm":
			p := strings.Split(parts[1], ",")
			name := p[0]
			bssAccessorsNeeded = append(bssAccessorsNeeded, name)
			symbols[accessorName(name)] = false
			ret = append(ret, line)

		case ".section":
			extractingText = false

			p := strings.Split(parts[1], ",")
			section := p[0]

			if section == ".rodata" || section == ".text.startup" || strings.HasPrefix(section, ".rodata.") {
				// Move .rodata to .text so it may be accessed
				// without a relocation. GCC with
				// -fmerge-constants will place strings into
				// separate sections, so we move all sections
				// named like .rodata. Also move .text.startup
				// so the self-test function is also in the
				// module.
				ret = append(ret, ".text  # "+section)
				break
			}

			switch section {
			case ".data", ".data.rel.ro.local":
				panic(fmt.Sprintf("bad section %q on line %d", parts[1], lineNo+1))

			case ".init_array":
				// init_array contains function pointers to
				// constructor functions. Since these must be
				// relocated, this section is moved to the end
				// of the file.
				extractedText = append(extractedText, line)
				extractingText = true

			default:
				ret = append(ret, line)
			}

		case ".text":
			extractingText = false
			fallthrough

		default:
			if extractingText {
				extractedText = append(extractedText, line)
				continue
			}

			if symbol, ok := isSymbolDef(line); ok {
				if isGlobal := symbols[symbol]; isGlobal {
					ret = append(ret, localTargetName(symbol)+":")
				}
			}

			if parts[0] == "leaq" {
				line = strings.Replace(line, "BORINGSSL_bcm_text_dummy_", "BORINGSSL_bcm_text_", -1)
			}
			ret = append(ret, line)
		}
	}

	ret = append(ret, "BORINGSSL_bcm_text_end:")

	// Emit redirector functions. Each is a single JMP instruction.
	for redirectorName, target := range redirectors {
		ret = append(ret, ".type "+redirectorName+", @function")
		ret = append(ret, redirectorName+":")
		ret = append(ret, "\tjmp "+target)
	}

	// Emit BSS accessor functions. Each is a single LEA followed by RET.
	for _, name := range bssAccessorsNeeded {
		funcName := accessorName(name)
		ret = append(ret, ".type "+funcName+", @function")
		ret = append(ret, funcName+":")
		ret = append(ret, "\tleaq "+name+"(%rip), %rax")
		ret = append(ret, "\tret")
	}

	// Emit an indirect reference to OPENSSL_ia32cap_P.
	if ia32capAddrNeeded {
		ret = append(ret, ".extern OPENSSL_ia32cap_P")
		ret = append(ret, ".type OPENSSL_ia32cap_addr,@object")
		ret = append(ret, ".size OPENSSL_ia32cap_addr,8")
		ret = append(ret, "OPENSSL_ia32cap_addr:")
		ret = append(ret, "\t.quad OPENSSL_ia32cap_P")
	}

	// Emit an array for storing the module hash.
	ret = append(ret, ".type BORINGSSL_bcm_text_hash,@object")
	ret = append(ret, ".size OPENSSL_ia32cap_addr,32")
	ret = append(ret, "BORINGSSL_bcm_text_hash:")
	for _, b := range uninitHashValue {
		ret = append(ret, ".byte 0x"+strconv.FormatUint(uint64(b), 16))
	}

	ret = append(ret, extractedText...)

	return ret
}

// accessorName returns the name of the accessor function for a BSS symbol
// named name.
func accessorName(name string) string {
	return name + "_bss_get"
}

// localTargetName returns the name of the local target label for a global
// symbol named name.
func localTargetName(name string) string {
	return ".L" + name + "_local_target"
}

// asLines appends the contents of path to lines. Local symbols are renamed
// using uniqueId to avoid collisions.
func asLines(lines []string, path string, uniqueId int) ([]string, error) {
	basename := symbolRuneOrUnderscore(filepath.Base(path))

	asFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer asFile.Close()

	var contents []string

	// localSymbols maps from the symbol name used in the input, to a
	// unique symbol name.
	localSymbols := make(map[string]string)

	scanner := bufio.NewScanner(asFile)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".L") && strings.HasSuffix(trimmed, ":") {
			symbol := trimmed[:len(trimmed)-1]
			mappedSymbol := fmt.Sprintf(".L%s_%d_%s", basename, uniqueId, symbol[2:])
			localSymbols[symbol] = mappedSymbol
			contents = append(contents, mappedSymbol+":")
			continue
		}

		contents = append(contents, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	for _, line := range contents {
		for symbol, mappedSymbol := range localSymbols {
			for i := strings.Index(line, symbol); i >= 0; i = strings.Index(line[i:], symbol) {
				before := ' '
				if i > 0 {
					before, _ = utf8.DecodeLastRuneInString(line[:i])
				}

				after, _ := utf8.DecodeRuneInString(line[i+len(symbol):])

				if !symbolRune(before) && !symbolRune(after) {
					line = strings.Replace(line, symbol, mappedSymbol, 1)
					i += len(mappedSymbol)
				} else {
					i += len(symbol)
				}
			}
		}

		lines = append(lines, line)
	}

	return lines, nil
}

func arLines(lines []string, arPath string) ([]string, error) {
	arFile, err := os.Open(arPath)
	if err != nil {
		return nil, err
	}
	defer arFile.Close()

	ar, err := ParseAR(arFile)
	if err != nil {
		return nil, err
	}

	if len(ar) != 1 {
		return nil, fmt.Errorf("expected one file in archive, but found %d", len(ar))
	}

	for _, contents := range ar {
		scanner := bufio.NewScanner(bytes.NewBuffer(contents))
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	return lines, nil
}

// validSymbolName returns true if s is a valid (non-local) name for a symbol.
func validSymbolName(s string) bool {
	if len(s) == 0 {
		return false
	}

	r, n := utf8.DecodeRuneInString(s)
	// symbols don't start with a digit.
	if r == utf8.RuneError || !symbolRune(r) || ('0' <= s[0] && s[0] <= '9') {
		return false
	}

	return strings.IndexFunc(s[n:], func(r rune) bool {
		return !symbolRune(r)
	}) == -1
}

// symbolRune returns true if r is valid in a symbol name.
func symbolRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '$' || r == '_'
}

// symbolRuneOrUnderscore maps s where runes valid in a symbol name map to
// themselves and all other runs map to underscore.
func symbolRuneOrUnderscore(s string) string {
	runes := make([]rune, 0, len(s))

	for _, r := range s {
		if symbolRune(r) {
			runes = append(runes, r)
		} else {
			runes = append(runes, '_')
		}
	}

	return string(runes)
}
