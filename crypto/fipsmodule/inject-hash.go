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

// inject-hash runs a binary compiled against a FIPS module that hasn't had the
// correct hash injected. That binary will fail the power-on integrity check
// and write the calcualted hash value to stderr. This script parses that and
// injects the calcualted value into the given object file.
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// uninitHashValue is the default hash value that we inject into the module.
// This value need only be distinct, i.e. so that we can safely
// search-and-replace it in an object file. This must match the value in bcm.c.
var uninitHashValue = [32]byte{
	0x5f, 0x30, 0xd1, 0x80, 0xe7, 0x9e, 0x8f, 0x8f, 0xdf, 0x8b, 0x93, 0xd4, 0x96, 0x36, 0x30, 0xcc, 0x30, 0xea, 0x38, 0x0f, 0x75, 0x56, 0x9a, 0x1b, 0x23, 0x2f, 0x7c, 0x79, 0xff, 0x1b, 0x2b, 0xca,
}

func do(outPath, arInput, binPath string) error {
	cmd := exec.Command(binPath)
	out, err := cmd.CombinedOutput()

	if err == nil {
		return errors.New("binary did not fail self test")
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 3 {
		return fmt.Errorf("too few lines in output: %q", out)
	}

	calculatedLine := lines[2]
	if !strings.HasPrefix(calculatedLine, "Calculated: ") {
		return errors.New("bad prefix of 3rd line: " + calculatedLine)
	}
	calculatedLine = calculatedLine[12:]
	calculated, err := hex.DecodeString(calculatedLine)
	if err != nil {
		return err
	}

	if len(calculated) != len(uninitHashValue) {
		return fmt.Errorf("unexpected length of calculated hash: got %d, want %d", len(calculated), len(uninitHashValue))
	}

	arFile, err := os.Open(arInput)
	if err != nil {
		return err
	}
	defer arFile.Close()

	ar, err := ParseAR(arFile)
	if err != nil {
		return err
	}

	if len(ar) != 1 {
		return fmt.Errorf("expected one file in archive, but found %d", len(ar))
	}

	var object []byte
	for _, contents := range ar {
		object = contents
	}

	offset := bytes.Index(object, uninitHashValue[:])
	if offset < 0 {
		return errors.New("did not find uninitialised hash value in object file")
	}

	if bytes.Index(object[offset+1:], uninitHashValue[:]) >= 0 {
		return errors.New("found two occurrences of uninitialised hash value in object file")
	}

	copy(object[offset:], calculated)

	if err := ioutil.WriteFile(outPath, object, 0644); err != nil {
		return err
	}

	return nil
}

func main() {
	arInput := flag.String("in", "", "Path to a .a file")
	outPath := flag.String("o", "", "Path to output object")
	bin := flag.String("bin", "", "Binary compiled with the FIPS module")

	flag.Parse()

	if err := do(*outPath, *arInput, *bin); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
