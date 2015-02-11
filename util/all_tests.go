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
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
)

// TODO(davidben): Link tests with the malloc shim and port -malloc-test to this runner.

var (
	useValgrind = flag.Bool("valgrind", false, "If true, run code under valgrind")
	buildDir    = flag.String("build-dir", "build", "The build directory to run the tests from.")
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

func main() {
	flag.Parse()

	var failed []test
	for _, test := range tests {
		fmt.Printf("%s\n", strings.Join([]string(test), " "))
		passed, err := runTest(test)
		if err != nil {
			fmt.Printf("%s failed to complete: %s\n", test[0], err.Error())
			failed = append(failed, test)
			continue
		}
		if !passed {
			fmt.Printf("%s failed to print PASS on the last line.\n", test[0])
			failed = append(failed, test)
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
}
