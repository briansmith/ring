// Copyright (c) 2016, Google Inc.
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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	buildDir     = flag.String("build-dir", "build", "Specifies the build directory to push.")
	device       = flag.String("device", "", "Specifies the device or emulator. See adb's -s argument.")
	aarch64      = flag.Bool("aarch64", false, "Build the test runners for aarch64 instead of arm.")
	arm          = flag.Int("arm", 7, "Which arm revision to build for.")
	allTestsArgs = flag.String("all-tests-args", "", "Specifies space-separated arguments to pass to all_tests.go")
	runnerArgs   = flag.String("runner-args", "", "Specifies space-separated arguments to pass to ssl/test/runner")
)

func adb(args ...string) error {
	if len(*device) > 0 {
		args = append([]string{"-s", *device}, args...)
	}
	cmd := exec.Command("adb", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func goTool(args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if *aarch64 {
		cmd.Env = append(cmd.Env, "GOARCH=arm64")
	} else {
		cmd.Env = append(cmd.Env, "GOARCH=arm")
		cmd.Env = append(cmd.Env, fmt.Sprintf("GOARM=%d", *arm))
	}
	return cmd.Run()
}

// setWorkingDirectory walks up directories as needed until the current working
// directory is the top of a BoringSSL checkout.
func setWorkingDirectory() {
	for i := 0; i < 64; i++ {
		if _, err := os.Stat("BUILDING.md"); err == nil {
			return
		}
		os.Chdir("..")
	}

	panic("Couldn't find BUILDING.md in a parent directory!")
}

type test []string

func parseTestConfig(filename string) ([]test, error) {
	in, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	decoder := json.NewDecoder(in)
	var result []test
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func copyFile(dst, src string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0777); err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func main() {
	flag.Parse()
	setWorkingDirectory()

	tests, err := parseTestConfig("util/all_tests.json")
	if err != nil {
		fmt.Printf("Failed to parse input: %s\n", err)
		os.Exit(1)
	}

	// Clear the target directory.
	if err := adb("shell", "rm -Rf /data/local/tmp/boringssl-tmp"); err != nil {
		fmt.Printf("Failed to clear target directory: %s\n", err)
		os.Exit(1)
	}

	// Stage everything in a temporary directory.
	tmpDir, err := ioutil.TempDir("", "boringssl-android")
	if err != nil {
		fmt.Printf("Error making temporary directory: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	seenBinary := make(map[string]struct{})
	binaries := []string{"ssl/test/bssl_shim"}
	files := []string{
		"BUILDING.md",
		"util/all_tests.json",
		"ssl/test/runner/cert.pem",
		"ssl/test/runner/channel_id_key.pem",
		"ssl/test/runner/ecdsa_cert.pem",
		"ssl/test/runner/ecdsa_key.pem",
		"ssl/test/runner/key.pem",
	}
	for _, test := range tests {
		if _, ok := seenBinary[test[0]]; !ok {
			binaries = append(binaries, test[0])
			seenBinary[test[0]] = struct{}{}
		}
		for _, arg := range test[1:] {
			if strings.Contains(arg, "/") {
				files = append(files, arg)
			}
		}
	}

	fmt.Printf("Copying test binaries...\n")
	for _, binary := range binaries {
		if err := copyFile(filepath.Join(tmpDir, "build", binary), filepath.Join(*buildDir, binary)); err != nil {
			fmt.Printf("Failed to copy %s: %s\n", binary, err)
			os.Exit(1)
		}
	}

	fmt.Printf("Copying data files...\n")
	for _, file := range files {
		if err := copyFile(filepath.Join(tmpDir, file), file); err != nil {
			fmt.Printf("Failed to copy %s: %s\n", file, err)
			os.Exit(1)
		}
	}

	fmt.Printf("Building all_tests...\n")
	if err := goTool("build", "-o", filepath.Join(tmpDir, "util/all_tests"), "util/all_tests.go"); err != nil {
		fmt.Printf("Error building all_tests.go: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Building runner...\n")
	if err := goTool("test", "-c", "-o", filepath.Join(tmpDir, "ssl/test/runner/runner"), "./ssl/test/runner/"); err != nil {
		fmt.Printf("Error building runner: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Uploading files...\n")
	if err := adb("push", "-p", tmpDir, "/data/local/tmp/boringssl-tmp"); err != nil {
		fmt.Printf("Failed to push runner: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Running unit tests...\n")
	if err := adb("shell", fmt.Sprintf("cd /data/local/tmp/boringssl-tmp && ./util/all_tests %s", *allTestsArgs)); err != nil {
		fmt.Printf("Failed to run unit tests: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Running SSL tests...\n")
	if err := adb("shell", fmt.Sprintf("cd /data/local/tmp/boringssl-tmp/ssl/test/runner && ./runner %s", *runnerArgs)); err != nil {
		fmt.Printf("Failed to run SSL tests: %s\n", err)
		os.Exit(1)
	}
}
