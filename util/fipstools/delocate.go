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
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func main() {
	// The .a file, if given, is expected to be an archive of textual
	// assembly sources. That's odd, but CMake really wants to create
	// archive files so it's the only way that we can make it work.
	arInput := flag.String("a", "", "Path to a .a file containing assembly sources")

	outFile := flag.String("o", "", "Path to output assembly")

	flag.Parse()

	var lines []string
	var err error
	if len(*arInput) > 0 {
		if lines, err = arLines(lines, *arInput); err != nil {
			panic(err)
		}
	}

	for i, path := range flag.Args() {
		if len(path) == 0 {
			continue
		}

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

func removeComment(line string) string {
	if i := strings.Index(line, "#"); i != -1 {
		return line[:i]
	}
	return line
}

// isSymbolDef returns detects whether line contains a (non-local) symbol
// definition. If so, it returns the symbol and true. Otherwise it returns ""
// and false.
func isSymbolDef(line string) (string, bool) {
	line = strings.TrimSpace(removeComment(line))

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

// threadLocalOffsetFunc describes a function that fetches the offset to symbol
// in the thread-local space and writes it to the given target register.
type threadLocalOffsetFunc struct {
	target string
	symbol string
}

type lineSource struct {
	lines  []string
	lineNo int
}

func (ls *lineSource) Next() (string, bool) {
	if ls.lineNo == len(ls.lines) {
		return "", false
	}

	ret := ls.lines[ls.lineNo]
	ls.lineNo++
	return ret, true
}

func (ls *lineSource) Unread() {
	ls.lineNo--
}

func parseInstruction(line string) (instr string, args []string) {
	line = strings.TrimSpace(line)
	if len(line) == 0 || line[0] == '#' {
		return "", nil
	}

	idx := strings.IndexFunc(line, unicode.IsSpace)
	if idx < 0 {
		return line, nil
	}

	instr = strings.TrimSpace(line[:idx])
	line = strings.TrimSpace(line[idx:])
	for len(line) > 0 {
		var inQuote bool
		var parens int
	Loop:
		for idx = 0; idx < len(line); idx++ {
			if inQuote {
				if line[idx] == '\\' {
					if idx == len(line)-1 {
						panic(fmt.Sprintf("could not parse %q", line))
					}
					idx++
				} else {
					inQuote = line[idx] != '"'
				}
				continue
			}
			switch line[idx] {
			case '"':
				inQuote = true
			case '(':
				parens++
			case ')':
				if parens == 0 {
					panic(fmt.Sprintf("could not parse %q", line))
				}
				parens--
			case ',':
				if parens == 0 {
					break Loop
				}
			case '#':
				line = line[:idx]
				break Loop
			}
		}

		if inQuote || parens > 0 {
			panic(fmt.Sprintf("could not parse %q", line))
		}

		args = append(args, strings.TrimSpace(line[:idx]))
		if idx < len(line) {
			// Skip the comma.
			line = line[idx+1:]
		} else {
			line = line[idx:]
		}
	}

	return
}

// transform performs a number of transformations on the given assembly code.
// See FIPS.md in the current directory for an overview.
func transform(lines []string, symbols map[string]bool) (ret []string) {
	ret = append(ret, ".text", "BORINGSSL_bcm_text_start:")

	// redirectors maps from out-call symbol name to the name of a
	// redirector function for that symbol.
	redirectors := make(map[string]string)

	// ia32capAddrDeltaNeeded is true iff OPENSSL_ia32cap_addr_delta has
	// been referenced and thus needs to be emitted outside the module.
	ia32capAddrDeltaNeeded := false

	// ia32capGetNeeded is true iff OPENSSL_ia32cap_get has been referenced
	// and thus needs to be emitted outside the module.
	ia32capGetNeeded := false

	// bssAccessorsNeeded maps the names of BSS variables for which
	// accessor functions need to be emitted outside of the module, to the
	// BSS symbols they point to. For example, “EVP_sha256_once” could map
	// to “.LEVP_sha256_once_local_target” or “EVP_sha256_once” (if .comm
	// was used).
	bssAccessorsNeeded := make(map[string]string)

	// threadLocalOffsets records the accessor functions needed for getting
	// offsets in the thread-local storage.
	threadLocalOffsets := make(map[string]threadLocalOffsetFunc)

	// gotpcrelExternalsNeeded is the set of symbols which are accessed via
	// the GOT and will need external relocations emitted.
	gotpcrelExternalsNeeded := make(map[string]struct{})

	source := &lineSource{lines: lines}

	for {
		line, ok := source.Next()
		if !ok {
			break
		}

		orig := line

		if strings.Contains(line, "OPENSSL_ia32cap_get@PLT") {
			ia32capGetNeeded = true
		}

		line = strings.Replace(line, "@PLT", "", -1)

		instr, args := parseInstruction(line)
		if len(instr) == 0 {
			ret = append(ret, line)
			continue
		}

		switch instr {
		case "call", "callq", "jmp", "jne", "jb", "jz", "jnz", "ja":
			target := args[0]
			// indirect via register or local label
			if strings.HasPrefix(target, "*") || isLocalLabel(target) {
				ret = append(ret, line)
				continue
			}

			if strings.HasSuffix(target, "_bss_get") || target == "OPENSSL_ia32cap_get" {
				// reference to a synthesised function. Don't
				// indirect it.
				ret = append(ret, line)
				continue
			}

			if isGlobal, ok := symbols[target]; ok {
				newTarget := target
				if isGlobal {
					newTarget = localTargetName(target)
				}
				ret = append(ret, fmt.Sprintf("\t%s %s", instr, newTarget))
				continue
			}

			redirectorName := "bcm_redirector_" + target
			ret = append(ret, fmt.Sprintf("\t%s %s", instr, redirectorName))
			redirectors[redirectorName] = target
			continue

		case "pushq":
			target := args[0]
			if strings.HasSuffix(target, "@GOTPCREL(%rip)") {
				target = target[:len(target)-15]
				if !symbols[target] {
					panic(fmt.Sprintf("Reference to unknown symbol on line %d: %s", source.lineNo, line))
				}

				ret = append(ret, "\tpushq %rax")
				ret = append(ret, "\tleaq "+localTargetName(target)+"(%rip), %rax")
				ret = append(ret, "\txchg %rax, (%rsp)")
				continue
			}

			ret = append(ret, line)
			continue

		case "leaq", "vmovq", "movq", "cmpq", "cmovneq", "cmoveq":
			if instr == "movq" && strings.Contains(line, "@GOTTPOFF(%rip)") {
				// GOTTPOFF are offsets into the thread-local
				// storage that are stored in the GOT. We have
				// to move these relocations out of the module,
				// but do not know whether rax is live at this
				// point. Thus a normal function call might
				// clobber a register and so we synthesize
				// different functions for writing to each
				// target register.
				//
				// (BoringSSL itself does not use __thread
				// variables, but ASAN and MSAN may add these
				// references for their bookkeeping.)
				targetRegister := args[1][1:]
				symbol := strings.SplitN(args[0], "@", 2)[0]
				functionName := fmt.Sprintf("BORINGSSL_bcm_tpoff_to_%s_for_%s", targetRegister, symbol)
				threadLocalOffsets[functionName] = threadLocalOffsetFunc{target: targetRegister, symbol: symbol}
				ret = append(ret, "leaq -128(%rsp), %rsp") // Clear the red zone.
				ret = append(ret, "\tcallq "+functionName+"\n")
				ret = append(ret, "leaq 128(%rsp), %rsp")
				continue
			}

			target := args[0]
			invertedCondition := ""

			if strings.HasSuffix(target, "(%rip)") {
				target = target[:len(target)-6]
				if isGlobal := symbols[target]; isGlobal {
					line = strings.Replace(line, target, localTargetName(target), 1)
				}

				if strings.Contains(line, "@GOTPCREL") && (instr == "movq" || instr == "vmovq" || instr == "cmoveq" || instr == "cmovneq") {
					line = strings.Replace(line, "@GOTPCREL", "", -1)
					target = strings.Replace(target, "@GOTPCREL", "", -1)
					var useGOT bool

					if isGlobal := symbols[target]; isGlobal {
						line = strings.Replace(line, target, localTargetName(target), 1)
						target = localTargetName(target)
					} else if target != "OPENSSL_ia32cap_P" && !strings.HasPrefix(target, "BORINGSSL_bcm_") {
						// If the symbol is defined external to libcrypto.a,
						// we need to use the GOT to avoid a runtime
						// relocation.
						useGOT = true
					}

					switch instr {
					case "cmoveq":
						invertedCondition = "ne"
					case "cmovneq":
						invertedCondition = "e"
					}

					if len(invertedCondition) > 0 {
						ret = append(ret, "\t# Was "+orig)
						ret = append(ret, "\tj"+invertedCondition+" 1f")
					}

					destination := args[1]
					if useGOT {
						if !strings.HasPrefix(destination, "%r") || destination == "%rsp" {
							// If it comes up, we can support %xmm* or memory references by
							// picking a spare register, but we must take care not to use a
							// register referenced in the destination.
							panic("destination must be a standard 64-bit register")
						}

						ret = append(ret, "leaq -128(%rsp), %rsp") // Clear the red zone.
						ret = append(ret, "pushf")
						ret = append(ret, fmt.Sprintf("leaq %s_GOTPCREL_external(%%rip), %s", target, destination))
						ret = append(ret, fmt.Sprintf("addq (%s), %s", destination, destination))
						ret = append(ret, fmt.Sprintf("movq (%s), %s", destination, destination))
						ret = append(ret, "popf")
						ret = append(ret, "leaq 128(%rsp), %rsp")

						gotpcrelExternalsNeeded[target] = struct{}{}
						continue
					}

					if strings.HasPrefix(destination, "%xmm") {
						if instr != "movq" && instr != "vmovq" {
							panic("unhandled: " + orig)
						}

						// MOV can target XMM
						// registers, but LEA cannot.
						ret = append(ret, "leaq -128(%rsp), %rsp") // Clear the red zone.
						ret = append(ret, "pushq %rax")
						ret = append(ret, "leaq "+target+"(%rip), %rax")
						ret = append(ret, "movq %rax, "+destination)
						ret = append(ret, "popq %rax")
						ret = append(ret, "leaq 128(%rsp), %rsp")

						continue
					}

					// A movq from the GOT is equivalent to a leaq. This symbol
					// is defined in libcrypto, so we can reference it directly.
					line = strings.Replace(line, instr, "leaq", 1)
					instr = "leaq"
				}

				if target == "OPENSSL_ia32cap_P" {
					if instr != "leaq" {
						panic("reference to OPENSSL_ia32cap_P needs to be changed to go through leaq or GOTPCREL")
					}
					if args[1][0] != '%' {
						panic("reference to OPENSSL_ia32cap_P must target a register.")
					}

					// We assume pushfq is safe, after
					// clearing the red zone, because any
					// signals will be delivered using
					// %rsp. Thus perlasm and
					// compiler-generated code must not use
					// %rsp as a general-purpose register.
					//
					// TODO(davidben): This messes up CFI
					// for a small window if %rsp is the CFI
					// register.
					ia32capAddrDeltaNeeded = true
					ret = append(ret, "leaq -128(%rsp), %rsp") // Clear the red zone.
					ret = append(ret, "pushfq")
					ret = append(ret, fmt.Sprintf("leaq OPENSSL_ia32cap_addr_delta(%%rip), %s", args[1]))
					ret = append(ret, fmt.Sprintf("addq (%s), %s", args[1], args[1]))
					ret = append(ret, "popfq")
					ret = append(ret, "leaq 128(%rsp), %rsp")
					continue
				}
			}

			ret = append(ret, line)
			if len(invertedCondition) > 0 {
				ret = append(ret, "1:")
			}
			continue

		case ".comm":
			name := args[0]
			bssAccessorsNeeded[name] = name
			ret = append(ret, line)

		case ".section":
			section := strings.Trim(args[0], "\"")
			if section == ".data.rel.ro" {
				// In a normal build, this is an indication of
				// a problem but any references from the module
				// to this section will result in a relocation
				// and thus will break the integrity check.
				// However, ASAN can generate these sections
				// and so we cannot forbid them.
				ret = append(ret, line)
				continue
			}

			sectionType, ok := sectionType(section)
			if !ok {
				panic(fmt.Sprintf("unknown section %q on line %d", section, source.lineNo))
			}

			switch sectionType {
			case ".rodata", ".text":
				// Move .rodata to .text so it may be accessed
				// without a relocation. GCC with
				// -fmerge-constants will place strings into
				// separate sections, so we move all sections
				// named like .rodata. Also move .text.startup
				// so the self-test function is also in the
				// module.
				ret = append(ret, ".text  # "+section)

			case ".data":
				panic(fmt.Sprintf("bad section %q on line %d", args[0], source.lineNo))

			case ".init_array", ".fini_array", ".ctors", ".dtors":
				// init_array/ctors/dtors contains function
				// pointers to constructor/destructor
				// functions. These contain relocations, but
				// they're in a different section anyway.
				ret = append(ret, line)

			case ".debug", ".note":
				ret = append(ret, line)

			case ".bss":
				ret = append(ret, line)

				var accessors map[string]string
				accessors, ret = handleBSSSection(ret, source)
				for accessor, name := range accessors {
					bssAccessorsNeeded[accessor] = name
				}

			default:
				panic(fmt.Sprintf("unknown section %q on line %d", section, source.lineNo))
			}

		default:
			if symbol, ok := isSymbolDef(line); ok {
				if isGlobal := symbols[symbol]; isGlobal {
					ret = append(ret, localTargetName(symbol)+":")
				}
			}

			ret = append(ret, line)
		}
	}

	ret = append(ret, ".text")
	ret = append(ret, "BORINGSSL_bcm_text_end:")

	// Emit redirector functions. Each is a single JMP instruction.
	var redirectorNames []string
	for name := range redirectors {
		redirectorNames = append(redirectorNames, name)
	}
	sort.Strings(redirectorNames)

	for _, name := range redirectorNames {
		ret = append(ret, ".type "+name+", @function")
		ret = append(ret, name+":")
		ret = append(ret, "\tjmp "+redirectors[name]+"@PLT")
	}

	var accessorNames []string
	for accessor := range bssAccessorsNeeded {
		accessorNames = append(accessorNames, accessor)
	}
	sort.Strings(accessorNames)

	// Emit BSS accessor functions. Each is a single LEA followed by RET.
	for _, name := range accessorNames {
		funcName := accessorName(name)
		ret = append(ret, ".type "+funcName+", @function")
		ret = append(ret, funcName+":")
		ret = append(ret, "\tleaq "+bssAccessorsNeeded[name]+"(%rip), %rax")
		ret = append(ret, "\tret")
	}

	// Emit an OPENSSL_ia32cap_get accessor.
	if ia32capGetNeeded {
		ret = append(ret, ".type OPENSSL_ia32cap_get, @function")
		ret = append(ret, "OPENSSL_ia32cap_get:")
		ret = append(ret, "\tleaq OPENSSL_ia32cap_P(%rip), %rax")
		ret = append(ret, "\tret")
	}

	// Emit an indirect reference to OPENSSL_ia32cap_P.
	if ia32capAddrDeltaNeeded {
		ret = append(ret, ".extern OPENSSL_ia32cap_P")
		ret = append(ret, ".type OPENSSL_ia32cap_addr_delta,@object")
		ret = append(ret, ".size OPENSSL_ia32cap_addr_delta,8")
		ret = append(ret, "OPENSSL_ia32cap_addr_delta:")
		ret = append(ret, "\t.quad OPENSSL_ia32cap_P-OPENSSL_ia32cap_addr_delta")
	}

	// Emit accessors for thread-local offsets.
	var threadAccessorNames []string
	for name := range threadLocalOffsets {
		threadAccessorNames = append(threadAccessorNames, name)
	}
	sort.Strings(threadAccessorNames)

	for _, name := range threadAccessorNames {
		f := threadLocalOffsets[name]

		ret = append(ret, ".type "+name+",@function")
		ret = append(ret, name+":")
		ret = append(ret, "\tmovq "+f.symbol+"@GOTTPOFF(%rip), %"+f.target)
		ret = append(ret, "\tret")
	}

	// Emit external relocations for GOTPCREL offsets.
	var gotpcrelExternalNames []string
	for name := range gotpcrelExternalsNeeded {
		gotpcrelExternalNames = append(gotpcrelExternalNames, name)
	}
	sort.Strings(gotpcrelExternalNames)

	for _, name := range gotpcrelExternalNames {
		ret = append(ret, ".type "+name+"_GOTPCREL_external, @object")
		ret = append(ret, ".size "+name+"_GOTPCREL_external, 8")
		ret = append(ret, name+"_GOTPCREL_external:")
		// Ideally this would be .quad foo@GOTPCREL, but clang's
		// assembler cannot emit a 64-bit GOTPCREL relocation. Instead,
		// we manually sign-extend the value, knowing that the GOT is
		// always at the end, thus foo@GOTPCREL has a positive value.
		ret = append(ret, "\t.long "+name+"@GOTPCREL")
		ret = append(ret, "\t.long 0")
	}

	// Emit an array for storing the module hash.
	ret = append(ret, ".type BORINGSSL_bcm_text_hash,@object")
	ret = append(ret, ".size BORINGSSL_bcm_text_hash,64")
	ret = append(ret, "BORINGSSL_bcm_text_hash:")
	for _, b := range uninitHashValue {
		ret = append(ret, ".byte 0x"+strconv.FormatUint(uint64(b), 16))
	}

	return ret
}

func isLocalLabel(label string) bool {
	if strings.HasPrefix(label, ".L") {
		return true
	}
	if strings.HasSuffix(label, "f") || strings.HasSuffix(label, "b") {
		label = label[:len(label)-1]
		return strings.IndexFunc(label, func(r rune) bool { return !unicode.IsNumber(r) }) == -1
	}
	return false
}

// handleBSSSection reads lines from source until the next section and adds a
// local symbol for each BSS symbol found.
func handleBSSSection(lines []string, source *lineSource) (map[string]string, []string) {
	accessors := make(map[string]string)

	for {
		line, ok := source.Next()
		if !ok {
			return accessors, lines
		}

		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) == 0 {
			lines = append(lines, line)
			continue
		}

		if strings.HasSuffix(parts[0], ":") {
			symbol := parts[0][:len(parts[0])-1]
			localSymbol := ".L" + symbol + "_local_target"

			lines = append(lines, line)
			lines = append(lines, localSymbol+":")

			accessors[symbol] = localSymbol
			continue
		}

		switch parts[0] {
		case ".text", ".section":
			source.Unread()
			return accessors, lines

		default:
			lines = append(lines, line)
		}
	}
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

// sectionType returns the type of a section. I.e. a section called “.text.foo”
// is a “.text” section.
func sectionType(section string) (string, bool) {
	if len(section) == 0 || section[0] != '.' {
		return "", false
	}

	i := strings.Index(section[1:], ".")
	if i != -1 {
		section = section[:i+1]
	}

	if strings.HasPrefix(section, ".debug_") {
		return ".debug", true
	}

	return section, true
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

	// localSymbols maps from the symbol name used in the input, to a
	// unique symbol name.
	localSymbols := make(map[string]string)

	scanner := bufio.NewScanner(asFile)
	var contents []string

	if len(lines) == 0 {
		// If this is the first assembly file, don't rewrite symbols.
		// Only all-but-one file needs to be rewritten and so time can
		// be saved by putting the (large) bcm.s first.
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			return nil, err
		}

		return lines, nil
	}

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

		contents = append(contents, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	for _, line := range contents {
		for symbol, mappedSymbol := range localSymbols {
			i := 0
			for match := strings.Index(line, symbol); match >= 0; match = strings.Index(line[i:], symbol) {
				i += match

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
