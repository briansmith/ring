// Copyright 2024 The BoringSSL Authors
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

//go:build ignore

package main

import (
	"bufio"
	"cmp"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"iter"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
)

var (
	outPath     = flag.String("out", "", "The path to write the results in JSON format")
	comparePath = flag.String("compare", "", "The path to a JSON file to compare against")
)

func sortedKeyValuePairs[K cmp.Ordered, V any](m map[K]V) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if !yield(k, m[k]) {
				return
			}
		}
	}
}

var copyrightRE = regexp.MustCompile(
	`Copyright ` +
		// Ignore (c) and (C)
		`(?:\([cC]\) )?` +
		// Capture the starting copyright year.
		`([0-9]+)` +
		// Ignore ending copyright year. OpenSSL's "copyright consolidation"
		// tool rewrites it anyway. We're just interested in looking for which
		// start years changed, to manually double-check.
		`(?:[-,][0-9]+)?` +
		// Some files have a comma after the years.
		`,?` +
		// Skip spaces.
		` *` +
		// Capture the name. Stop at punctuation and don't pick up trailing
		// spaces. We don't want to pick up things like "All Rights Reserved".
		// This does drop things like ", Inc", but this is good enough for a
		// summary to double-check an otherwise mostly automated process.
		`([-a-zA-Z ]*[-a-zA-Z])`)

type CopyrightInfo struct {
	Name      string
	StartYear int
}

type FileInfo struct {
	CopyrightInfos []CopyrightInfo
}

func (f *FileInfo) MergeFrom(other FileInfo) {
	f.CopyrightInfos = append(f.CopyrightInfos, other.CopyrightInfos...)
}

func summarize(info FileInfo) map[string]int {
	ret := map[string]int{}
	for _, c := range info.CopyrightInfos {
		name := c.Name
		// Apply the same mapping as OpenSSL's "copyright consolidation" script.
		if name == "The OpenSSL Project" || name == "Eric Young" {
			name = "The OpenSSL Project Authors"
		}
		if old, ok := ret[name]; !ok || old > c.StartYear {
			ret[name] = c.StartYear
		}
	}
	return ret
}

func process(path string) (info FileInfo, err error) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		m := copyrightRE.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		var year int
		year, err = strconv.Atoi(m[1])
		if err != nil {
			err = fmt.Errorf("error parsing year %q: %s", m[1], err)
			return
		}
		info.CopyrightInfos = append(info.CopyrightInfos, CopyrightInfo{Name: m[2], StartYear: year})
	}
	err = scanner.Err()
	return
}

func main() {
	flag.Parse()

	infos := map[string]FileInfo{}
	for _, path := range flag.Args() {
		info, err := process(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error processing %q: %s\n", path, err)
			os.Exit(1)
		}
		infos[path] = info
	}

	if len(*outPath) != 0 {
		data, err := json.Marshal(infos)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error serializing results: %s\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outPath, data, 0666); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing results: %s\n", err)
			os.Exit(1)
		}
	}

	if len(*comparePath) == 0 {
		// Print what we have and return.
		for path, info := range sortedKeyValuePairs(infos) {
			for _, c := range info.CopyrightInfos {
				fmt.Printf("%s: %d %s\n", path, c.StartYear, c.Name)
			}
		}
		return
	}

	oldData, err := os.ReadFile(*comparePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %s\n", err)
		os.Exit(1)
	}
	var oldInfos map[string]FileInfo
	if err := json.Unmarshal(oldData, &oldInfos); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding %q: %s\n", *comparePath, err)
		os.Exit(1)
	}
	// Output in CSV, so it is easy to paste into a spreadsheet.
	fmt.Printf("Path,Name,Old Start Year,New Start Year\n")
	for path, info := range sortedKeyValuePairs(infos) {
		oldInfo, ok := oldInfos[path]
		if !ok {
			fmt.Printf("%s: file not previously present\n", path)
			continue
		}

		summary := summarize(info)
		oldSummary := summarize(oldInfo)
		for name, year := range sortedKeyValuePairs(summary) {
			oldYear, ok := oldSummary[name]
			if !ok {
				fmt.Printf("%s,%s,-1,%d\n", path, name, year)
			} else if year != oldYear {
				fmt.Printf("%s,%s,%d,%d\n", path, name, oldYear, year)
			}
		}
		for oldName, oldYear := range sortedKeyValuePairs(oldSummary) {
			if _, ok := summary[oldName]; !ok {
				fmt.Printf("%s,%s,%d,-1\n", path, oldName, oldYear)
			}
		}
	}
}
