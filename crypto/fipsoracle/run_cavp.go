// run_cavp.go processes CAVP input files and generates suitable response
// files, optionally comparing the results against the provided FAX files.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	binaryDir = flag.String("bin-dir", "", "Directory containing fipsoracle binaries")
)

// test describes a single request file.
type test struct {
	// inFile is the base of the filename without an extension, i.e.
	// “ECBMCT128”.
	inFile string
	// args are the arguments (not including the input filename) to the
	// oracle binary.
	args []string
	// noFAX, if true, indicates that the output cannot be compared against
	// the FAX file. (E.g. because the primitive is non-deterministic.)
	noFAX bool
}

// testSuite describes a series of tests that are handled by a single oracle
// binary.
type testSuite struct {
	// directory is the name of the directory in the CAVP input, i.e. “AES”.
	directory string
	// binary is the name of the binary that can process these tests.
	binary string
	tests  []test
}

var aesGCMTests = testSuite{
	"AES_GCM",
	"cavp_aes_gcm_test",
	[]test{
		{"gcmDecrypt128", []string{"dec", "aes-128-gcm"}, false},
		{"gcmDecrypt256", []string{"dec", "aes-256-gcm"}, false},
		{"gcmEncryptIntIV128", []string{"enc", "aes-128-gcm"}, true},
		{"gcmEncryptIntIV256", []string{"enc", "aes-256-gcm"}, true},
	},
}

var aesTests = testSuite{
	"AES",
	"cavp_aes_test",
	[]test{
		{"CBCGFSbox128", []string{"aes-128-cbc"}, false},
		{"CBCGFSbox192", []string{"aes-192-cbc"}, false},
		{"CBCGFSbox256", []string{"aes-256-cbc"}, false},
		{"CBCKeySbox128", []string{"aes-128-cbc"}, false},
		{"CBCKeySbox192", []string{"aes-192-cbc"}, false},
		{"CBCKeySbox256", []string{"aes-256-cbc"}, false},
		{"CBCMMT128", []string{"aes-128-cbc"}, false},
		{"CBCMMT192", []string{"aes-192-cbc"}, false},
		{"CBCMMT256", []string{"aes-256-cbc"}, false},
		{"CBCVarKey128", []string{"aes-128-cbc"}, false},
		{"CBCVarKey192", []string{"aes-192-cbc"}, false},
		{"CBCVarKey256", []string{"aes-256-cbc"}, false},
		{"CBCVarTxt128", []string{"aes-128-cbc"}, false},
		{"CBCVarTxt192", []string{"aes-192-cbc"}, false},
		{"CBCVarTxt256", []string{"aes-256-cbc"}, false},
		{"ECBGFSbox128", []string{"aes-128-ecb"}, false},
		{"ECBGFSbox192", []string{"aes-192-ecb"}, false},
		{"ECBGFSbox256", []string{"aes-256-ecb"}, false},
		{"ECBKeySbox128", []string{"aes-128-ecb"}, false},
		{"ECBKeySbox192", []string{"aes-192-ecb"}, false},
		{"ECBKeySbox256", []string{"aes-256-ecb"}, false},
		{"ECBMMT128", []string{"aes-128-ecb"}, false},
		{"ECBMMT192", []string{"aes-192-ecb"}, false},
		{"ECBMMT256", []string{"aes-256-ecb"}, false},
		{"ECBVarKey128", []string{"aes-128-ecb"}, false},
		{"ECBVarKey192", []string{"aes-192-ecb"}, false},
		{"ECBVarKey256", []string{"aes-256-ecb"}, false},
		{"ECBVarTxt128", []string{"aes-128-ecb"}, false},
		{"ECBVarTxt192", []string{"aes-192-ecb"}, false},
		{"ECBVarTxt256", []string{"aes-256-ecb"}, false},
	},
}

// AES Monte-Carlo tests need a different binary.
//{"ECBMCT128", []string{"aes-128-ecb"}, false},
//{"ECBMCT192", []string{"aes-192-ecb"}, false},
//{"ECBMCT256", []string{"aes-256-ecb"}, false},
//{"CBCMCT128", []string{"aes-128-cbc"}, false},
//{"CBCMCT192", []string{"aes-192-cbc"}, false},
//{"CBCMCT256", []string{"aes-256-cbc"}, false},

var ecdsa2PKVTests = testSuite{
	"ECDSA2",
	"cavp_ecdsa2_pkv_test",
	[]test{{"PKV", nil, false}},
}

var ecdsa2SigVerTests = testSuite{
	"ECDSA2",
	"cavp_ecdsa2_sigver_test",
	[]test{{"SigVer", nil, false}},
}

var allTestSuites = []*testSuite{
	&aesGCMTests,
	&aesTests,
	&ecdsa2PKVTests,
	&ecdsa2SigVerTests,
}

func main() {
	flag.Parse()

	if len(*binaryDir) == 0 {
		fmt.Fprintf(os.Stderr, "Must give -bin-dir\n")
		os.Exit(1)
	}

	for _, suite := range allTestSuites {
		for _, test := range suite.tests {
			if err := doTest(suite, test); err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				os.Exit(2)
			}

			if !test.noFAX {
				if err := compareFAX(suite, test); err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err)
					os.Exit(3)
				}
			}
		}
	}
}

func doTest(suite *testSuite, test test) error {
	binary := filepath.Join(*binaryDir, suite.binary)

	var args []string
	args = append(args, test.args...)
	args = append(args, filepath.Join(suite.directory, "req", test.inFile+".req"))

	outPath := filepath.Join(suite.directory, "resp", test.inFile+".resp")
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("cannot open output file for %q %q: %s", suite.directory, test.inFile, err)
	}
	defer outFile.Close()

	cmd := exec.Command(binary, args...)
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot run command for %q %q: %s", suite.directory, test.inFile, err)
	}

	return nil
}

func canonicalizeLine(in string) string {
	if strings.HasPrefix(in, "Result = P (") {
		return "Result = P"
	}
	if strings.HasPrefix(in, "Result = F (") {
		return "Result = F"
	}
	return in
}

func compareFAX(suite *testSuite, test test) error {
	respPath := filepath.Join(suite.directory, "resp", test.inFile+".resp")
	respFile, err := os.Open(respPath)
	if err != nil {
		return fmt.Errorf("cannot read output of %q %q: %s", suite.directory, test.inFile, err)
	}
	defer respFile.Close()

	faxPath := filepath.Join(suite.directory, "fax", test.inFile+".fax")
	faxFile, err := os.Open(faxPath)
	if err != nil {
		return fmt.Errorf("cannot open fax file for %q %q: %s", suite.directory, test.inFile, err)
	}
	defer faxFile.Close()

	respScanner := bufio.NewScanner(respFile)
	faxScanner := bufio.NewScanner(faxFile)

	lineNo := 0
	inHeader := true

	for respScanner.Scan() {
		lineNo++
		respLine := respScanner.Text()
		var faxLine string

		if inHeader && (len(respLine) == 0 || respLine[0] == '#') {
			continue
		}

		for {
			haveFaxLine := false

			if inHeader {
				for faxScanner.Scan() {
					faxLine = faxScanner.Text()
					if len(faxLine) != 0 && faxLine[0] != '#' {
						haveFaxLine = true
						break
					}
				}

				inHeader = false
			} else {
				if faxScanner.Scan() {
					faxLine = faxScanner.Text()
					haveFaxLine = true
				}
			}

			if !haveFaxLine {
				return fmt.Errorf("resp file is longer than fax for %q %q", suite.directory, test.inFile)
			}

			if strings.HasPrefix(faxLine, " (Reason: ") {
				continue
			}

			break
		}

		if canonicalizeLine(faxLine) == canonicalizeLine(respLine) {
			continue
		}

		return fmt.Errorf("resp and fax differ at line %d for %q %q: %q vs %q", lineNo, suite.directory, test.inFile, respLine, faxLine)
	}

	if faxScanner.Scan() {
		return fmt.Errorf("fax file is longer than resp for %q %q", suite.directory, test.inFile)
	}

	return nil
}
