package main

import (
	"bytes"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime"
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
	// expectedVersion, if non-zero, specifies the TLS version that must be
	// negotiated.
	expectedVersion uint16
	// messageLen is the length, in bytes, of the test message that will be
	// sent.
	messageLen int
	// certFile is the path to the certificate to use for the server.
	certFile string
	// keyFile is the path to the private key to use for the server.
	keyFile string
	// resumeSession controls whether a second connection should be tested
	// which resumes the first session.
	resumeSession bool
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
		testType: serverTest,
		name:     "BadRSAVersion",
		config: Config{
			CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA},
			Bugs: ProtocolBugs{
				RsaClientKeyExchangeVersion: VersionTLS11,
			},
		},
		shouldFail:    true,
		expectedError: ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
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
	{
		name: "ClientCertificateTypes",
		config: Config{
			ClientAuth: RequestClientCert,
			ClientCertificateTypes: []byte{
				CertTypeDSSSign,
				CertTypeRSASign,
				CertTypeECDSASign,
			},
		},
		flags: []string{"-expect-certificate-types", string([]byte{
			CertTypeDSSSign,
			CertTypeRSASign,
			CertTypeECDSASign,
		})},
	},
	{
		name: "NoClientCertificate",
		config: Config{
			ClientAuth: RequireAnyClientCert,
		},
		shouldFail:         true,
		expectedLocalError: "client didn't provide a certificate",
	},
	{
		name: "UnauthenticatedECDH",
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				UnauthenticatedECDH: true,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
	},
	{
		name: "SkipServerKeyExchange",
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				SkipServerKeyExchange: true,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
	},
	{
		name: "SkipChangeCipherSpec-Client",
		config: Config{
			Bugs: ProtocolBugs{
				SkipChangeCipherSpec: true,
			},
		},
		shouldFail:    true,
		expectedError: ":HANDSHAKE_RECORD_BEFORE_CCS:",
	},
	{
		testType: serverTest,
		name:     "SkipChangeCipherSpec-Server",
		config: Config{
			Bugs: ProtocolBugs{
				SkipChangeCipherSpec: true,
			},
		},
		shouldFail:    true,
		expectedError: ":HANDSHAKE_RECORD_BEFORE_CCS:",
	},
	{
		testType: serverTest,
		name:     "SkipChangeCipherSpec-Server-NPN",
		config: Config{
			NextProtos: []string{"bar"},
			Bugs: ProtocolBugs{
				SkipChangeCipherSpec: true,
			},
		},
		flags: []string{
			"-advertise-npn", "\x03foo\x03bar\x03baz",
		},
		shouldFail:    true,
		expectedError: ":HANDSHAKE_RECORD_BEFORE_CCS:",
	},
	{
		name: "FragmentAcrossChangeCipherSpec-Client",
		config: Config{
			Bugs: ProtocolBugs{
				FragmentAcrossChangeCipherSpec: true,
			},
		},
		shouldFail:    true,
		expectedError: ":HANDSHAKE_RECORD_BEFORE_CCS:",
	},
	{
		testType: serverTest,
		name:     "FragmentAcrossChangeCipherSpec-Server",
		config: Config{
			Bugs: ProtocolBugs{
				FragmentAcrossChangeCipherSpec: true,
			},
		},
		shouldFail:    true,
		expectedError: ":HANDSHAKE_RECORD_BEFORE_CCS:",
	},
	{
		testType: serverTest,
		name:     "FragmentAcrossChangeCipherSpec-Server-NPN",
		config: Config{
			NextProtos: []string{"bar"},
			Bugs: ProtocolBugs{
				FragmentAcrossChangeCipherSpec: true,
			},
		},
		flags: []string{
			"-advertise-npn", "\x03foo\x03bar\x03baz",
		},
		shouldFail:    true,
		expectedError: ":HANDSHAKE_RECORD_BEFORE_CCS:",
	},
	{
		testType: serverTest,
		name:     "EarlyChangeCipherSpec-server-1",
		config: Config{
			Bugs: ProtocolBugs{
				EarlyChangeCipherSpec: 1,
			},
		},
		shouldFail:    true,
		expectedError: ":CCS_RECEIVED_EARLY:",
	},
	{
		testType: serverTest,
		name:     "EarlyChangeCipherSpec-server-2",
		config: Config{
			Bugs: ProtocolBugs{
				EarlyChangeCipherSpec: 2,
			},
		},
		shouldFail:    true,
		expectedError: ":CCS_RECEIVED_EARLY:",
	},
	{
		name: "SkipNewSessionTicket",
		config: Config{
			Bugs: ProtocolBugs{
				SkipNewSessionTicket: true,
			},
		},
		shouldFail:    true,
		expectedError: ":CCS_RECEIVED_EARLY:",
	},
	{
		name: "FalseStart-SessionTicketsDisabled",
		config: Config{
			CipherSuites:           []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			NextProtos:             []string{"foo"},
			SessionTicketsDisabled: true,
		},
		flags: []string{
			"-false-start",
			"-select-next-proto", "foo",
		},
	},
	{
		testType: serverTest,
		name:     "SendV2ClientHello",
		config: Config{
			// Choose a cipher suite that does not involve
			// elliptic curves, so no extensions are
			// involved.
			CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA},
			Bugs: ProtocolBugs{
				SendV2ClientHello: true,
			},
		},
	},
	{
		testType: serverTest,
		name:     "FallbackSCSV",
		config: Config{
			MaxVersion: VersionTLS11,
			Bugs: ProtocolBugs{
				SendFallbackSCSV: true,
			},
		},
		shouldFail:    true,
		expectedError: ":INAPPROPRIATE_FALLBACK:",
	},
	{
		testType: serverTest,
		name:     "FallbackSCSV-VersionMatch",
		config: Config{
			Bugs: ProtocolBugs{
				SendFallbackSCSV: true,
			},
		},
	},
}

func doExchange(test *testCase, config *Config, conn net.Conn, messageLen int) error {
	var tlsConn *Conn
	if test.testType == clientTest {
		tlsConn = Server(conn, config)
	} else {
		config.InsecureSkipVerify = true
		tlsConn = Client(conn, config)
	}

	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	if vers := tlsConn.ConnectionState().Version; test.expectedVersion != 0 && vers != test.expectedVersion {
		return fmt.Errorf("got version %x, expected %x", vers, test.expectedVersion)
	}

	if messageLen < 0 {
		// Read until EOF.
		_, err := io.Copy(ioutil.Discard, tlsConn)
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

func openSocketPair() (shimEnd *os.File, conn net.Conn) {
	socks, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		panic(err)
	}

	syscall.CloseOnExec(socks[0])
	syscall.CloseOnExec(socks[1])
	shimEnd = os.NewFile(uintptr(socks[0]), "shim end")
	connFile := os.NewFile(uintptr(socks[1]), "our end")
	conn, err = net.FileConn(connFile)
	if err != nil {
		panic(err)
	}
	connFile.Close()
	if err != nil {
		panic(err)
	}
	return shimEnd, conn
}

func runTest(test *testCase, buildDir string) error {
	shimEnd, conn := openSocketPair()
	shimEndResume, connResume := openSocketPair()

	shim_path := path.Join(buildDir, "ssl/test/bssl_shim")
	flags := []string{}
	if test.testType == clientTest {
		flags = append(flags, "client")
	} else {
		flags = append(flags, "server")
	}

	if test.resumeSession {
		flags = append(flags, "resume")
	} else {
		flags = append(flags, "normal")
	}

	if test.testType == serverTest {
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
	shim.ExtraFiles = []*os.File{shimEnd, shimEndResume}
	shim.Stdin = os.Stdin
	var stdoutBuf, stderrBuf bytes.Buffer
	shim.Stdout = &stdoutBuf
	shim.Stderr = &stderrBuf

	if err := shim.Start(); err != nil {
		panic(err)
	}
	shimEnd.Close()
	shimEndResume.Close()

	config := test.config
	config.ClientSessionCache = NewLRUClientSessionCache(1)
	if test.testType == clientTest {
		if len(config.Certificates) == 0 {
			config.Certificates = []Certificate{getRSACertificate()}
		}
	}

	err := doExchange(test, &config, conn, test.messageLen)
	conn.Close()
	if err == nil && test.resumeSession {
		err = doExchange(test, &config, connResume, test.messageLen)
		connResume.Close()
	}

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
	flag    string
}{
	{"SSL3", VersionSSL30, "-no-ssl3"},
	{"TLS1", VersionTLS10, "-no-tls1"},
	{"TLS11", VersionTLS11, "-no-tls11"},
	{"TLS12", VersionTLS12, "-no-tls12"},
}

var testCipherSuites = []struct {
	name string
	id   uint16
}{
	{"3DES-SHA", TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	{"AES128-GCM", TLS_RSA_WITH_AES_128_GCM_SHA256},
	{"AES128-SHA", TLS_RSA_WITH_AES_128_CBC_SHA},
	{"AES256-GCM", TLS_RSA_WITH_AES_256_GCM_SHA384},
	{"AES256-SHA", TLS_RSA_WITH_AES_256_CBC_SHA},
	{"DHE-RSA-3DES-SHA", TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA},
	{"DHE-RSA-AES128-GCM", TLS_DHE_RSA_WITH_AES_128_GCM_SHA256},
	{"DHE-RSA-AES128-SHA", TLS_DHE_RSA_WITH_AES_128_CBC_SHA},
	{"DHE-RSA-AES256-GCM", TLS_DHE_RSA_WITH_AES_256_GCM_SHA384},
	{"DHE-RSA-AES256-SHA", TLS_DHE_RSA_WITH_AES_256_CBC_SHA},
	{"ECDHE-ECDSA-AES128-GCM", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	{"ECDHE-ECDSA-AES128-SHA", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
	{"ECDHE-ECDSA-AES256-SHA", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
	{"ECDHE-ECDSA-RC4-SHA", TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
	{"ECDHE-RSA-3DES-SHA", TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
	{"ECDHE-RSA-AES128-GCM", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	{"ECDHE-RSA-AES128-SHA", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
	{"ECDHE-RSA-AES256-GCM", TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	{"ECDHE-RSA-AES256-SHA", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
	{"ECDHE-RSA-RC4-SHA", TLS_ECDHE_RSA_WITH_RC4_128_SHA},
	{"RC4-MD5", TLS_RSA_WITH_RC4_128_MD5},
	{"RC4-SHA", TLS_RSA_WITH_RC4_128_SHA},
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

			// Go's TLS implementation only implements session
			// resumption with tickets, so SSLv3 cannot resume
			// sessions.
			resumeSession := ver.version != VersionSSL30

			testCases = append(testCases, testCase{
				testType: clientTest,
				name:     ver.name + "-" + suite.name + "-client",
				config: Config{
					MinVersion:   ver.version,
					MaxVersion:   ver.version,
					CipherSuites: []uint16{suite.id},
					Certificates: []Certificate{cert},
				},
				resumeSession: resumeSession,
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
					certFile:      certFile,
					keyFile:       keyFile,
					resumeSession: resumeSession,
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

func addCBCSplittingTests() {
	testCases = append(testCases, testCase{
		name: "CBCRecordSplitting",
		config: Config{
			MaxVersion:   VersionTLS10,
			MinVersion:   VersionTLS10,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		},
		messageLen: -1, // read until EOF
		flags: []string{
			"-async",
			"-write-different-record-sizes",
			"-cbc-record-splitting",
		},
	})
	testCases = append(testCases, testCase{
		name: "CBCRecordSplittingPartialWrite",
		config: Config{
			MaxVersion:   VersionTLS10,
			MinVersion:   VersionTLS10,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		},
		messageLen: -1, // read until EOF
		flags: []string{
			"-async",
			"-write-different-record-sizes",
			"-cbc-record-splitting",
			"-partial-write",
		},
	})
}

func addClientAuthTests() {
	// Add a dummy cert pool to stress certificate authority parsing.
	// TODO(davidben): Add tests that those values parse out correctly.
	certPool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(rsaCertificate.Certificate[0])
	if err != nil {
		panic(err)
	}
	certPool.AddCert(cert)

	for _, ver := range tlsVersions {
		if ver.version == VersionSSL30 {
			// TODO(davidben): The Go implementation does not
			// correctly compute CertificateVerify hashes for SSLv3.
			continue
		}

		var cipherSuites []uint16
		if ver.version >= VersionTLS12 {
			// Pick a SHA-256 cipher suite. The Go implementation
			// does not correctly handle client auth with a SHA-384
			// cipher suite.
			cipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		}

		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     ver.name + "-Client-ClientAuth-RSA",
			config: Config{
				MinVersion:   ver.version,
				MaxVersion:   ver.version,
				CipherSuites: cipherSuites,
				ClientAuth:   RequireAnyClientCert,
				ClientCAs:    certPool,
			},
			flags: []string{
				"-cert-file", rsaCertificateFile,
				"-key-file", rsaKeyFile,
			},
		})
		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     ver.name + "-Client-ClientAuth-ECDSA",
			config: Config{
				MinVersion:   ver.version,
				MaxVersion:   ver.version,
				CipherSuites: cipherSuites,
				ClientAuth:   RequireAnyClientCert,
				ClientCAs:    certPool,
			},
			flags: []string{
				"-cert-file", ecdsaCertificateFile,
				"-key-file", ecdsaKeyFile,
			},
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     ver.name + "-Server-ClientAuth-RSA",
			config: Config{
				Certificates: []Certificate{rsaCertificate},
			},
			flags: []string{"-require-any-client-certificate"},
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     ver.name + "-Server-ClientAuth-ECDSA",
			config: Config{
				Certificates: []Certificate{ecdsaCertificate},
			},
			flags: []string{"-require-any-client-certificate"},
		})
	}
}

// Adds tests that try to cover the range of the handshake state machine, under
// various conditions. Some of these are redundant with other tests, but they
// only cover the synchronous case.
func addStateMachineCoverageTests(async bool, splitHandshake bool) {
	var suffix string
	var flags []string
	var maxHandshakeRecordLength int
	if async {
		suffix = "-Async"
		flags = append(flags, "-async")
	} else {
		suffix = "-Sync"
	}
	if splitHandshake {
		suffix += "-SplitHandshakeRecords"
		maxHandshakeRecordLength = 10
	}

	// Basic handshake, with resumption. Client and server.
	testCases = append(testCases, testCase{
		name: "Basic-Client" + suffix,
		config: Config{
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: flags,
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "Basic-Server" + suffix,
		config: Config{
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: flags,
	})

	// No session ticket support; server doesn't send NewSessionTicket.
	testCases = append(testCases, testCase{
		name: "SessionTicketsDisabled-Client" + suffix,
		config: Config{
			SessionTicketsDisabled: true,
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: flags,
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SessionTicketsDisabled-Server" + suffix,
		config: Config{
			SessionTicketsDisabled: true,
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: flags,
	})

	// NPN on client and server; results in post-handshake message.
	testCases = append(testCases, testCase{
		name: "NPN-Client" + suffix,
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			NextProtos:   []string{"foo"},
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: append(flags, "-select-next-proto", "foo"),
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "NPN-Server" + suffix,
		config: Config{
			NextProtos: []string{"bar"},
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: append(flags,
			"-advertise-npn", "\x03foo\x03bar\x03baz",
			"-expect-next-proto", "bar"),
	})

	// Client does False Start and negotiates NPN.
	testCases = append(testCases, testCase{
		name: "FalseStart" + suffix,
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			NextProtos:   []string{"foo"},
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: append(flags,
			"-false-start",
			"-select-next-proto", "foo"),
		resumeSession: true,
	})

	// TLS client auth.
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "ClientAuth-Client" + suffix,
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			ClientAuth:   RequireAnyClientCert,
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: append(flags,
			"-cert-file", rsaCertificateFile,
			"-key-file", rsaKeyFile),
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ClientAuth-Server" + suffix,
		config: Config{
			Certificates: []Certificate{rsaCertificate},
		},
		flags: append(flags, "-require-any-client-certificate"),
	})
}

func addVersionNegotiationTests() {
	for i, shimVers := range tlsVersions {
		// Assemble flags to disable all newer versions on the shim.
		var flags []string
		for _, vers := range tlsVersions[i+1:] {
			flags = append(flags, vers.flag)
		}

		for _, runnerVers := range tlsVersions {
			expectedVersion := shimVers.version
			if runnerVers.version < shimVers.version {
				expectedVersion = runnerVers.version
			}
			suffix := shimVers.name + "-" + runnerVers.name

			testCases = append(testCases, testCase{
				testType: clientTest,
				name:     "VersionNegotiation-Client-" + suffix,
				config: Config{
					MaxVersion: runnerVers.version,
				},
				flags:           flags,
				expectedVersion: expectedVersion,
			})

			// TODO(davidben): Implement SSLv3 as a client in the runner.
			if expectedVersion > VersionSSL30 {
				testCases = append(testCases, testCase{
					testType: serverTest,
					name:     "VersionNegotiation-Server-" + suffix,
					config: Config{
						MaxVersion: runnerVers.version,
					},
					flags:           flags,
					expectedVersion: expectedVersion,
				})
			}
		}
	}
}

func worker(statusChan chan statusMsg, c chan *testCase, buildDir string, wg *sync.WaitGroup) {
	defer wg.Done()

	for test := range c {
		statusChan <- statusMsg{test: test, started: true}
		err := runTest(test, buildDir)
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
	var flagNumWorkers *int = flag.Int("num-workers", runtime.NumCPU(), "The number of workers to run in parallel.")
	var flagBuildDir *string = flag.String("build-dir", "../../../build", "The build directory to run the shim from.")

	flag.Parse()

	addCipherSuiteTests()
	addBadECDSASignatureTests()
	addCBCPaddingTests()
	addCBCSplittingTests()
	addClientAuthTests()
	addVersionNegotiationTests()
	for _, async := range []bool{false, true} {
		for _, splitHandshake := range []bool{false, true} {
			addStateMachineCoverageTests(async, splitHandshake)
		}
	}

	var wg sync.WaitGroup

	numWorkers := *flagNumWorkers

	statusChan := make(chan statusMsg, numWorkers)
	testChan := make(chan *testCase, numWorkers)
	doneChan := make(chan struct{})

	go statusPrinter(doneChan, statusChan, len(testCases))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(statusChan, testChan, *flagBuildDir, &wg)
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
