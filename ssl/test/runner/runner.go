package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

var useValgrind = flag.Bool("valgrind", false, "If true, run code under valgrind")

const (
	rsaCertificateFile   = "cert.pem"
	ecdsaCertificateFile = "ecdsa_cert.pem"
)

const (
	rsaKeyFile   = "key.pem"
	ecdsaKeyFile = "ecdsa_key.pem"
)

var rsaCertificate, ecdsaCertificate Certificate

func initCertificates() {
	var err error
	rsaCertificate, err = LoadX509KeyPair(rsaCertificateFile, rsaKeyFile)
	if err != nil {
		panic(err)
	}

	ecdsaCertificate, err = LoadX509KeyPair(ecdsaCertificateFile, ecdsaKeyFile)
	if err != nil {
		panic(err)
	}
}

var certificateOnce sync.Once

func getRSACertificate() Certificate {
	certificateOnce.Do(initCertificates)
	return rsaCertificate
}

func getECDSACertificate() Certificate {
	certificateOnce.Do(initCertificates)
	return ecdsaCertificate
}

type testType int

const (
	clientTest testType = iota
	serverTest
)

type testCase struct {
	testType      testType
	name          string
	config        Config
	shouldFail    bool
	expectedError string
	// expectedLocalError, if not empty, contains a substring that must be
	// found in the local error.
	expectedLocalError string
	// messageLen is the length, in bytes, of the test message that will be
	// sent.
	messageLen int
	// certFile is the path to the certificate to use for the server.
	certFile string
	// keyFile is the path to the private key to use for the server.
	keyFile string
	// flags, if not empty, contains a list of command-line flags that will
	// be passed to the shim program.
	flags []string
}

var testCases = []testCase{
	{
		name: "BadRSASignature",
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				InvalidSKXSignature: true,
			},
		},
		shouldFail:    true,
		expectedError: ":BAD_SIGNATURE:",
	},
	{
		name: "BadECDSASignature",
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				InvalidSKXSignature: true,
			},
			Certificates: []Certificate{getECDSACertificate()},
		},
		shouldFail:    true,
		expectedError: ":BAD_SIGNATURE:",
	},
	{
		name: "BadECDSACurve",
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				InvalidSKXCurve: true,
			},
			Certificates: []Certificate{getECDSACertificate()},
		},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	},
	{
		name: "NoFallbackSCSV",
		config: Config{
			Bugs: ProtocolBugs{
				FailIfNotFallbackSCSV: true,
			},
		},
		shouldFail:         true,
		expectedLocalError: "no fallback SCSV found",
	},
	{
		name: "FallbackSCSV",
		config: Config{
			Bugs: ProtocolBugs{
				FailIfNotFallbackSCSV: true,
			},
		},
		flags: []string{"-fallback-scsv"},
	},
	{
		testType: serverTest,
		name:     "ServerNameExtension",
		config: Config{
			ServerName: "example.com",
		},
		flags: []string{"-expect-server-name", "example.com"},
	},
	{
		testType: clientTest,
		name:     "DuplicateExtensionClient",
		config: Config{
			Bugs: ProtocolBugs{
				DuplicateExtension: true,
			},
		},
		shouldFail:         true,
		expectedLocalError: "remote error: error decoding message",
	},
	{
		testType: serverTest,
		name:     "DuplicateExtensionServer",
		config: Config{
			Bugs: ProtocolBugs{
				DuplicateExtension: true,
			},
		},
		shouldFail:         true,
		expectedLocalError: "remote error: error decoding message",
	},
}

func doExchange(tlsConn *Conn, messageLen int) error {
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	if messageLen == 0 {
		messageLen = 32
	}
	testMessage := make([]byte, messageLen)
	for i := range testMessage {
		testMessage[i] = 0x42
	}
	tlsConn.Write(testMessage)

	buf := make([]byte, len(testMessage))
	_, err := io.ReadFull(tlsConn, buf)
	if err != nil {
		return err
	}

	for i, v := range buf {
		if v != testMessage[i]^0xff {
			return fmt.Errorf("bad reply contents at byte %d", i)
		}
	}

	return nil
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

func gdbOf(path string, args ...string) *exec.Cmd {
	xtermArgs := []string{"-e", "gdb", "--args"}
	xtermArgs = append(xtermArgs, path)
	xtermArgs = append(xtermArgs, args...)

	return exec.Command("xterm", xtermArgs...)
}

func runTest(test *testCase) error {
	socks, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		panic(err)
	}

	syscall.CloseOnExec(socks[0])
	syscall.CloseOnExec(socks[1])
	shimEnd := os.NewFile(uintptr(socks[0]), "shim end")
	connFile := os.NewFile(uintptr(socks[1]), "our end")
	conn, err := net.FileConn(connFile)
	connFile.Close()
	if err != nil {
		panic(err)
	}

	const shim_path = "../../../build/ssl/test/bssl_shim"
	flags := []string{}
	if test.testType == clientTest {
		flags = append(flags, "client")
	} else {
		flags = append(flags, "server")

		flags = append(flags, "-key-file")
		if test.keyFile == "" {
			flags = append(flags, rsaKeyFile)
		} else {
			flags = append(flags, test.keyFile)
		}

		flags = append(flags, "-cert-file")
		if test.certFile == "" {
			flags = append(flags, rsaCertificateFile)
		} else {
			flags = append(flags, test.certFile)
		}
	}
	flags = append(flags, test.flags...)

	var shim *exec.Cmd
	if *useValgrind {
		shim = valgrindOf(false, shim_path, flags...)
	} else {
		shim = exec.Command(shim_path, flags...)
	}
	// shim = gdbOf(shim_path, flags...)
	shim.ExtraFiles = []*os.File{shimEnd}
	shim.Stdin = os.Stdin
	var stdoutBuf, stderrBuf bytes.Buffer
	shim.Stdout = &stdoutBuf
	shim.Stderr = &stderrBuf

	if err := shim.Start(); err != nil {
		panic(err)
	}
	shimEnd.Close()

	config := test.config

	var tlsConn *Conn
	if test.testType == clientTest {
		if len(config.Certificates) == 0 {
			config.Certificates = []Certificate{getRSACertificate()}
		}
		tlsConn = Server(conn, &config)
	} else {
		config.InsecureSkipVerify = true
		tlsConn = Client(conn, &config)
	}
	err = doExchange(tlsConn, test.messageLen)

	conn.Close()
	childErr := shim.Wait()

	stdout := string(stdoutBuf.Bytes())
	stderr := string(stderrBuf.Bytes())
	failed := err != nil || childErr != nil
	correctFailure := len(test.expectedError) == 0 || strings.Contains(stdout, test.expectedError)
	localError := "none"
	if err != nil {
		localError = err.Error()
	}
	if len(test.expectedLocalError) != 0 {
		correctFailure = correctFailure && strings.Contains(localError, test.expectedLocalError)
	}

	if failed != test.shouldFail || failed && !correctFailure {
		childError := "none"
		if childErr != nil {
			childError = childErr.Error()
		}

		var msg string
		switch {
		case failed && !test.shouldFail:
			msg = "unexpected failure"
		case !failed && test.shouldFail:
			msg = "unexpected success"
		case failed && !correctFailure:
			msg = "bad error (wanted '" + test.expectedError + "' / '" + test.expectedLocalError + "')"
		default:
			panic("internal error")
		}

		return fmt.Errorf("%s: local error '%s', child error '%s', stdout:\n%s\nstderr:\n%s", msg, localError, childError, string(stdoutBuf.Bytes()), stderr)
	}

	if !*useValgrind && len(stderr) > 0 {
		println(stderr)
	}

	return nil
}

var tlsVersions = []struct {
	name    string
	version uint16
}{
	{"SSL3", VersionSSL30},
	{"TLS1", VersionTLS10},
	{"TLS11", VersionTLS11},
	{"TLS12", VersionTLS12},
}

var testCipherSuites = []struct {
	name string
	id   uint16
}{
	{"3DES-SHA", TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	{"AES128-SHA", TLS_RSA_WITH_AES_128_CBC_SHA},
	{"AES256-SHA", TLS_RSA_WITH_AES_256_CBC_SHA},
	{"ECDHE-ECDSA-AES128-GCM", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	{"ECDHE-ECDSA-AES128-SHA", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
	{"ECDHE-ECDSA-AES256-SHA", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
	{"ECDHE-ECDSA-RC4-SHA", TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
	{"ECDHE-RSA-3DES-SHA", TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
	{"ECDHE-RSA-AES128-GCM", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	{"ECDHE-RSA-AES256-GCM", TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	{"ECDHE-RSA-AES128-SHA", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
	{"ECDHE-RSA-AES256-SHA", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
	{"ECDHE-RSA-RC4-SHA", TLS_ECDHE_RSA_WITH_RC4_128_SHA},
	{"RC4-SHA", TLS_RSA_WITH_RC4_128_SHA},
	{"RC4-MD5", TLS_RSA_WITH_RC4_128_MD5},
}

func addCipherSuiteTests() {
	for _, suite := range testCipherSuites {
		var cert Certificate
		var certFile string
		var keyFile string
		if strings.Contains(suite.name, "ECDSA") {
			cert = getECDSACertificate()
			certFile = ecdsaCertificateFile
			keyFile = ecdsaKeyFile
		} else {
			cert = getRSACertificate()
			certFile = rsaCertificateFile
			keyFile = rsaKeyFile
		}

		for _, ver := range tlsVersions {
			if ver.version != VersionTLS12 && strings.HasSuffix(suite.name, "-GCM") {
				continue
			}

			testCases = append(testCases, testCase{
				testType: clientTest,
				name:     ver.name + "-" + suite.name + "-client",
				config: Config{
					MinVersion:   ver.version,
					MaxVersion:   ver.version,
					CipherSuites: []uint16{suite.id},
					Certificates: []Certificate{cert},
				},
			})

			// Go's TLS implementation implements SSLv3 as a server,
			// but not as a client.
			//
			// TODO(davidben): Implement SSLv3 as a client too to
			// exercise that code.
			if ver.version != VersionSSL30 {
				testCases = append(testCases, testCase{
					testType: serverTest,
					name:     ver.name + "-" + suite.name + "-server",
					config: Config{
						MinVersion:   ver.version,
						MaxVersion:   ver.version,
						CipherSuites: []uint16{suite.id},
						Certificates: []Certificate{cert},
					},
					certFile: certFile,
					keyFile:  keyFile,
				})
			}
		}
	}
}

func addBadECDSASignatureTests() {
	for badR := BadValue(1); badR < NumBadValues; badR++ {
		for badS := BadValue(1); badS < NumBadValues; badS++ {
			testCases = append(testCases, testCase{
				name: fmt.Sprintf("BadECDSA-%d-%d", badR, badS),
				config: Config{
					CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
					Certificates: []Certificate{getECDSACertificate()},
					Bugs: ProtocolBugs{
						BadECDSAR: badR,
						BadECDSAS: badS,
					},
				},
				shouldFail:    true,
				expectedError: "SIGNATURE",
			})
		}
	}
}

func addCBCPaddingTests() {
	testCases = append(testCases, testCase{
		name: "MaxCBCPadding",
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			Bugs: ProtocolBugs{
				MaxPadding: true,
			},
		},
		messageLen: 12, // 20 bytes of SHA-1 + 12 == 0 % block size
	})
	testCases = append(testCases, testCase{
		name: "BadCBCPadding",
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			Bugs: ProtocolBugs{
				PaddingFirstByteBad: true,
			},
		},
		shouldFail:    true,
		expectedError: "DECRYPTION_FAILED_OR_BAD_RECORD_MAC",
	})
	// OpenSSL previously had an issue where the first byte of padding in
	// 255 bytes of padding wasn't checked.
	testCases = append(testCases, testCase{
		name: "BadCBCPadding255",
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			Bugs: ProtocolBugs{
				MaxPadding:               true,
				PaddingFirstByteBadIf255: true,
			},
		},
		messageLen:    12, // 20 bytes of SHA-1 + 12 == 0 % block size
		shouldFail:    true,
		expectedError: "DECRYPTION_FAILED_OR_BAD_RECORD_MAC",
	})
}

func worker(statusChan chan statusMsg, c chan *testCase, wg *sync.WaitGroup) {
	defer wg.Done()

	for test := range c {
		statusChan <- statusMsg{test: test, started: true}
		err := runTest(test)
		statusChan <- statusMsg{test: test, err: err}
	}
}

type statusMsg struct {
	test    *testCase
	started bool
	err     error
}

func statusPrinter(doneChan chan struct{}, statusChan chan statusMsg, total int) {
	var started, done, failed, lineLen int
	defer close(doneChan)

	for msg := range statusChan {
		if msg.started {
			started++
		} else {
			done++
		}

		fmt.Printf("\x1b[%dD\x1b[K", lineLen)

		if msg.err != nil {
			fmt.Printf("FAILED (%s)\n%s\n", msg.test.name, msg.err)
			failed++
		}
		line := fmt.Sprintf("%d/%d/%d/%d", failed, done, started, total)
		lineLen = len(line)
		os.Stdout.WriteString(line)
	}
}

func main() {
	var flagTest *string = flag.String("test", "", "The name of a test to run, or empty to run all tests")

	flag.Parse()

	addCipherSuiteTests()
	addBadECDSASignatureTests()
	addCBCPaddingTests()

	var wg sync.WaitGroup

	const numWorkers = 64

	statusChan := make(chan statusMsg, numWorkers)
	testChan := make(chan *testCase, numWorkers)
	doneChan := make(chan struct{})

	go statusPrinter(doneChan, statusChan, len(testCases))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(statusChan, testChan, &wg)
	}

	for i := range testCases {
		if len(*flagTest) == 0 || *flagTest == testCases[i].name {
			testChan <- &testCases[i]
		}
	}

	close(testChan)
	wg.Wait()
	close(statusChan)
	<-doneChan

	fmt.Printf("\n")
}
