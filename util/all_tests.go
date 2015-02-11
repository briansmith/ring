/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

// TODO(davidben): Link tests with the malloc shim and port -malloc-test to this runner.

var (
	useValgrind = flag.Bool("valgrind", false, "If true, run code under valgrind")
	buildDir    = flag.String("build-dir", "build", "The build directory to run the tests from.")
	jsonOutput  = flag.String("json-output", "", "The file to output JSON results to.")
)

type test []string

var tests = []test{
	{"crypto/base64/base64_test"},
	{"crypto/bio/bio_test"},
	{"crypto/bn/bn_test"},
	{"crypto/bytestring/bytestring_test"},
	{"crypto/cipher/aead_test", "aes-128-gcm", "crypto/cipher/test/aes_128_gcm_tests.txt"},
	{"crypto/cipher/aead_test", "aes-128-key-wrap", "crypto/cipher/test/aes_128_key_wrap_tests.txt"},
	{"crypto/cipher/aead_test", "aes-256-gcm", "crypto/cipher/test/aes_256_gcm_tests.txt"},
	{"crypto/cipher/aead_test", "aes-256-key-wrap", "crypto/cipher/test/aes_256_key_wrap_tests.txt"},
	{"crypto/cipher/aead_test", "chacha20-poly1305", "crypto/cipher/test/chacha20_poly1305_tests.txt"},
	{"crypto/cipher/aead_test", "rc4-md5-tls", "crypto/cipher/test/rc4_md5_tls_tests.txt"},
	{"crypto/cipher/aead_test", "rc4-sha1-tls", "crypto/cipher/test/rc4_sha1_tls_tests.txt"},
	{"crypto/cipher/aead_test", "aes-128-cbc-sha1-tls", "crypto/cipher/test/aes_128_cbc_sha1_tls_tests.txt"},
	{"crypto/cipher/aead_test", "aes-128-cbc-sha1-tls-implicit-iv", "crypto/cipher/test/aes_128_cbc_sha1_tls_implicit_iv_tests.txt"},
	{"crypto/cipher/aead_test", "aes-128-cbc-sha256-tls", "crypto/cipher/test/aes_128_cbc_sha256_tls_tests.txt"},
	{"crypto/cipher/aead_test", "aes-256-cbc-sha1-tls", "crypto/cipher/test/aes_256_cbc_sha1_tls_tests.txt"},
	{"crypto/cipher/aead_test", "aes-256-cbc-sha1-tls-implicit-iv", "crypto/cipher/test/aes_256_cbc_sha1_tls_implicit_iv_tests.txt"},
	{"crypto/cipher/aead_test", "aes-256-cbc-sha256-tls", "crypto/cipher/test/aes_256_cbc_sha256_tls_tests.txt"},
	{"crypto/cipher/aead_test", "aes-256-cbc-sha384-tls", "crypto/cipher/test/aes_256_cbc_sha384_tls_tests.txt"},
	{"crypto/cipher/aead_test", "des-ede3-cbc-sha1-tls", "crypto/cipher/test/des_ede3_cbc_sha1_tls_tests.txt"},
	{"crypto/cipher/aead_test", "des-ede3-cbc-sha1-tls-implicit-iv", "crypto/cipher/test/des_ede3_cbc_sha1_tls_implicit_iv_tests.txt"},
	{"crypto/cipher/aead_test", "rc4-md5-ssl3", "crypto/cipher/test/rc4_md5_ssl3_tests.txt"},
	{"crypto/cipher/aead_test", "rc4-sha1-ssl3", "crypto/cipher/test/rc4_sha1_ssl3_tests.txt"},
	{"crypto/cipher/aead_test", "aes-128-cbc-sha1-ssl3", "crypto/cipher/test/aes_128_cbc_sha1_ssl3_tests.txt"},
	{"crypto/cipher/aead_test", "aes-256-cbc-sha1-ssl3", "crypto/cipher/test/aes_256_cbc_sha1_ssl3_tests.txt"},
	{"crypto/cipher/aead_test", "des-ede3-cbc-sha1-ssl3", "crypto/cipher/test/des_ede3_cbc_sha1_ssl3_tests.txt"},
	{"crypto/cipher/cipher_test", "crypto/cipher/test/cipher_test.txt"},
	{"crypto/constant_time_test"},
	{"crypto/dh/dh_test"},
	{"crypto/digest/digest_test"},
	{"crypto/dsa/dsa_test"},
	{"crypto/ec/ec_test"},
	{"crypto/ec/example_mul"},
	{"crypto/ecdsa/ecdsa_test"},
	{"crypto/err/err_test"},
	{"crypto/evp/evp_test"},
	{"crypto/evp/pbkdf_test"},
	{"crypto/hkdf/hkdf_test"},
	{"crypto/hmac/hmac_test"},
	{"crypto/lhash/lhash_test"},
	{"crypto/modes/gcm_test"},
	{"crypto/pkcs8/pkcs12_test"},
	{"crypto/rsa/rsa_test"},
	{"crypto/x509/pkcs7_test"},
	{"crypto/x509v3/tab_test"},
	{"crypto/x509v3/v3name_test"},
	{"ssl/pqueue/pqueue_test"},
	{"ssl/ssl_test"},
}

// testOutput is a representation of Chromium's JSON test result format. See
// https://www.chromium.org/developers/the-json-test-results-format
type testOutput struct {
	Version           int                   `json:"version"`
	Interrupted       bool                  `json:"interrupted"`
	PathDelimiter     string                `json:"path_delimiter"`
	SecondsSinceEpoch float64               `json:"seconds_since_epoch"`
	NumFailuresByType map[string]int        `json:"num_failures_by_type"`
	Tests             map[string]testResult `json:"tests"`
}

type testResult struct {
	Actual   string `json:"actual"`
	Expected string `json:"expected"`
}

func newTestOutput() *testOutput {
	return &testOutput{
		Version:           3,
		PathDelimiter:     ".",
		SecondsSinceEpoch: float64(time.Now().UnixNano()) / float64(time.Second/time.Nanosecond),
		NumFailuresByType: make(map[string]int),
		Tests:             make(map[string]testResult),
	}
}

func (t *testOutput) addResult(name, result string) {
	if _, found := t.Tests[name]; found {
		panic(name)
	}
	t.Tests[name] = testResult{Actual: result, Expected: "PASS"}
	t.NumFailuresByType[result]++
}

func (t *testOutput) writeTo(name string) error {
	file, err := os.Create(name)
	if err != nil {
		return err
	}
	defer file.Close()
	out, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	_, err = file.Write(out)
	return err
}

func valgrindOf(dbAttach bool, path string, args ...string) *exec.Cmd {
	valgrindArgs := []string{"--error-exitcode=99", "--track-origins=yes", "--leak-check=full"}
	if dbAttach {
		valgrindArgs = append(valgrindArgs, "--db-attach=yes", "--db-command=xterm -e gdb -nw %f %p")
	}
	valgrindArgs = append(valgrindArgs, path)
	valgrindArgs = append(valgrindArgs, args...)

	return exec.Command("valgrind", valgrindArgs...)
}

func runTest(test test) (passed bool, err error) {
	prog := path.Join(*buildDir, test[0])
	args := test[1:]
	var cmd *exec.Cmd
	if *useValgrind {
		cmd = valgrindOf(false, prog, args...)
	} else {
		cmd = exec.Command(prog, args...)
	}
	var stdoutBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return false, err
	}
	if err := cmd.Wait(); err != nil {
		return false, err
	}

	// Account for Windows line-endings.
	stdout := bytes.Replace(stdoutBuf.Bytes(), []byte("\r\n"), []byte("\n"), -1)

	if bytes.HasSuffix(stdout, []byte("PASS\n")) &&
		(len(stdout) == 5 || stdout[len(stdout)-6] == '\n') {
		return true, nil
	}
	return false, nil
}

// shortTestName returns the short name of a test. It assumes that any argument
// which ends in .txt is a path to a data file and not relevant to the test's
// uniqueness.
func shortTestName(test test) string {
	var args []string
	for _, arg := range test {
		if !strings.HasSuffix(arg, ".txt") {
			args = append(args, arg)
		}
	}
	return strings.Join(args, " ")
}

func main() {
	flag.Parse()

	testOutput := newTestOutput()
	var failed []test
	for _, test := range tests {
		fmt.Printf("%s\n", strings.Join([]string(test), " "))

		name := shortTestName(test)
		passed, err := runTest(test)
		if err != nil {
			fmt.Printf("%s failed to complete: %s\n", test[0], err)
			failed = append(failed, test)
			testOutput.addResult(name, "CRASHED")
		} else if !passed {
			fmt.Printf("%s failed to print PASS on the last line.\n", test[0])
			failed = append(failed, test)
			testOutput.addResult(name, "FAIL")
		} else {
			testOutput.addResult(name, "PASS")
		}
	}

	if len(failed) == 0 {
		fmt.Printf("\nAll tests passed!\n")
	} else {
		fmt.Printf("\n%d of %d tests failed:\n", len(failed), len(tests))
		for _, test := range failed {
			fmt.Printf("\t%s\n", strings.Join([]string(test), " "))
		}
	}

	if *jsonOutput != "" {
		if err := testOutput.writeTo(*jsonOutput); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
	}
}
