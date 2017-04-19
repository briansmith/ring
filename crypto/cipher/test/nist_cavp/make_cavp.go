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

// The make_cavp utility generates cipher_test input files from
// NIST CAVP Known Answer Test response (.rsp) files.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var (
	cipher             = flag.String("cipher", "", "The name of the cipher (supported: aes, tdes). Required.")
	cmdLineLabelStr    = flag.String("extra-labels", "", "Comma-separated list of additional label pairs to add (e.g. 'Cipher=AES-128-CBC,Operation=ENCRYPT')")
	swapIVAndPlaintext = flag.Bool("swap-iv-plaintext", false, "When processing CBC vector files for CTR mode, swap IV and plaintext.")
)

// The set of supported values for the -cipher flag.
var allCiphers = map[string]interface{}{"aes": nil, "tdes": nil}

// The character to delimit key-value pairs throughout the file ('=' or ':').
var kvDelim rune

func parseKeyValue(s string) (key, value string) {
	if kvDelim == 0 {
		i := strings.IndexAny(s, "=:")
		if i != -1 {
			kvDelim = rune(s[i])
		}
	}
	if i := strings.IndexRune(s, kvDelim); kvDelim != 0 && i != -1 {
		key, value = s[:i], s[i+1:]
	} else {
		key = s
	}
	return strings.TrimSpace(key), strings.TrimSpace(value)
}

type kvPair struct {
	key, value string
}

var kvTranslations = map[kvPair]kvPair{
	{"ENCRYPT", ""}:    {"Operation", "ENCRYPT"},
	{"DECRYPT", ""}:    {"Operation", "DECRYPT"},
	{"COUNT", ""}:      {"Count", ""},
	{"KEY", ""}:        {"Key", ""}, // AES
	{"KEYs", ""}:       {"Key", ""}, // TDES
	{"PLAINTEXT", ""}:  {"Plaintext", ""},
	{"CIPHERTEXT", ""}: {"Ciphertext", ""},
	{"COUNT", ""}:      {"", ""}, // delete
}

func translateKeyValue(key, value string) (string, string) {
	if t, ok := kvTranslations[kvPair{key, ""}]; ok {
		if len(t.value) == 0 && len(value) != 0 {
			return t.key, value
		}
		return t.key, t.value
	}
	if t, ok := kvTranslations[kvPair{key, value}]; ok {
		return t.key, t.value
	}
	return key, value
}

func printKeyValue(key, value string) {
	if len(value) == 0 {
		fmt.Println(key)
	} else {
		fmt.Printf("%s: %s\n", key, value)
	}
}

func generateTest(r io.Reader) {
	s := bufio.NewScanner(r)

	// Label blocks consist of lines of the form "[key]" or "[key =
	// value]". |labels| holds keys and values of the most recent block
	// of labels.
	var labels map[string]string

	// Auxiliary labels passed as a flag.
	cmdLineLabels := make(map[string]string)
	if len(*cmdLineLabelStr) != 0 {
		pairs := strings.Split(*cmdLineLabelStr, ",")
		for _, p := range pairs {
			key, value := parseKeyValue(p)
			cmdLineLabels[key] = value
		}
	}

	kvDelim = 0

	// Whether we are in a test or a label section.
	inLabels := false
	inTest := false

	n := 0
	for s.Scan() {
		n++
		line := s.Text()
		l := strings.TrimSpace(line)
		l = strings.SplitN(l, "#", 2)[0] // Trim trailing comments.

		// Blank line.
		if len(l) == 0 {
			if inTest {
				fmt.Println()
			}
			inTest = false
			inLabels = false
			continue
		}

		// Label section.
		if l[0] == '[' {
			if l[len(l)-1] != ']' {
				log.Fatalf("line #%d invalid: %q", n, line)
			}
			if !inLabels {
				labels = make(map[string]string)
				inLabels = true
			}

			k, v := parseKeyValue(l[1 : len(l)-1])
			k, v = translateKeyValue(k, v)
			if len(k) != 0 {
				labels[k] = v
			}

			continue
		}

		// Repeat the label map at the beginning of each test section.
		if !inTest {
			inTest = true
			for k, v := range cmdLineLabels {
				printKeyValue(k, v)
			}
			for k, v := range labels {
				printKeyValue(k, v)
			}
		}

		k, v := parseKeyValue(l)
		k, v = translateKeyValue(k, v)
		if *cipher == "tdes" && k == "Key" {
			v += v + v // Key1=Key2=Key3
		}
		if len(k) != 0 {
			printKeyValue(k, v)
		}
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: make_cavp <file 1> [<file 2> ...]")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if *swapIVAndPlaintext {
		kvTranslations[kvPair{"PLAINTEXT", ""}] = kvPair{"IV", ""}
		kvTranslations[kvPair{"IV", ""}] = kvPair{"Plaintext", ""}
	}

	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "no input files\n\n")
		flag.Usage()
		os.Exit(1)
	}
	if _, ok := allCiphers[*cipher]; len(*cipher) == 0 || !ok {
		fmt.Fprintf(os.Stderr, "invalid cipher: %s\n\n", *cipher)
		flag.Usage()
		os.Exit(1)
	}

	args := append([]string{"make_cavp"}, os.Args[1:]...)
	fmt.Printf("# Generated by %q\n\n", strings.Join(args, " "))

	for i, p := range flag.Args() {
		f, err := os.Open(p)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		fmt.Printf("# File %d: %s\n\n", i+1, p)
		generateTest(f)
	}
}
