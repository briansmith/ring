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

package runner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	useValgrind     = flag.Bool("valgrind", false, "If true, run code under valgrind")
	useGDB          = flag.Bool("gdb", false, "If true, run BoringSSL code under gdb")
	useLLDB         = flag.Bool("lldb", false, "If true, run BoringSSL code under lldb")
	flagDebug       = flag.Bool("debug", false, "Hexdump the contents of the connection")
	mallocTest      = flag.Int64("malloc-test", -1, "If non-negative, run each test with each malloc in turn failing from the given number onwards.")
	mallocTestDebug = flag.Bool("malloc-test-debug", false, "If true, ask bssl_shim to abort rather than fail a malloc. This can be used with a specific value for --malloc-test to identity the malloc failing that is causing problems.")
	jsonOutput      = flag.String("json-output", "", "The file to output JSON results to.")
	pipe            = flag.Bool("pipe", false, "If true, print status output suitable for piping into another program.")
	testToRun       = flag.String("test", "", "The name of a test to run, or empty to run all tests")
	numWorkers      = flag.Int("num-workers", runtime.NumCPU(), "The number of workers to run in parallel.")
	shimPath        = flag.String("shim-path", "../../../build/ssl/test/bssl_shim", "The location of the shim binary.")
	resourceDir     = flag.String("resource-dir", ".", "The directory in which to find certificate and key files.")
	fuzzer          = flag.Bool("fuzzer", false, "If true, tests against a BoringSSL built in fuzzer mode.")
	transcriptDir   = flag.String("transcript-dir", "", "The directory in which to write transcripts.")
	idleTimeout     = flag.Duration("idle-timeout", 15*time.Second, "The number of seconds to wait for a read or write to bssl_shim.")
	deterministic   = flag.Bool("deterministic", false, "If true, uses a deterministic PRNG in the runner.")
)

type testCert int

const (
	testCertRSA testCert = iota
	testCertRSA1024
	testCertECDSAP256
	testCertECDSAP384
	testCertECDSAP521
)

const (
	rsaCertificateFile       = "cert.pem"
	rsa1024CertificateFile   = "rsa_1024_cert.pem"
	ecdsaP256CertificateFile = "ecdsa_p256_cert.pem"
	ecdsaP384CertificateFile = "ecdsa_p384_cert.pem"
	ecdsaP521CertificateFile = "ecdsa_p521_cert.pem"
)

const (
	rsaKeyFile       = "key.pem"
	rsa1024KeyFile   = "rsa_1024_key.pem"
	ecdsaP256KeyFile = "ecdsa_p256_key.pem"
	ecdsaP384KeyFile = "ecdsa_p384_key.pem"
	ecdsaP521KeyFile = "ecdsa_p521_key.pem"
	channelIDKeyFile = "channel_id_key.pem"
)

var (
	rsaCertificate       Certificate
	rsa1024Certificate   Certificate
	ecdsaP256Certificate Certificate
	ecdsaP384Certificate Certificate
	ecdsaP521Certificate Certificate
)

var testCerts = []struct {
	id                testCert
	certFile, keyFile string
	cert              *Certificate
}{
	{
		id:       testCertRSA,
		certFile: rsaCertificateFile,
		keyFile:  rsaKeyFile,
		cert:     &rsaCertificate,
	},
	{
		id:       testCertRSA1024,
		certFile: rsa1024CertificateFile,
		keyFile:  rsa1024KeyFile,
		cert:     &rsa1024Certificate,
	},
	{
		id:       testCertECDSAP256,
		certFile: ecdsaP256CertificateFile,
		keyFile:  ecdsaP256KeyFile,
		cert:     &ecdsaP256Certificate,
	},
	{
		id:       testCertECDSAP384,
		certFile: ecdsaP384CertificateFile,
		keyFile:  ecdsaP384KeyFile,
		cert:     &ecdsaP384Certificate,
	},
	{
		id:       testCertECDSAP521,
		certFile: ecdsaP521CertificateFile,
		keyFile:  ecdsaP521KeyFile,
		cert:     &ecdsaP521Certificate,
	},
}

var channelIDKey *ecdsa.PrivateKey
var channelIDBytes []byte

var testOCSPResponse = []byte{1, 2, 3, 4}
var testSCTList = []byte{5, 6, 7, 8}

func initCertificates() {
	for i := range testCerts {
		cert, err := LoadX509KeyPair(path.Join(*resourceDir, testCerts[i].certFile), path.Join(*resourceDir, testCerts[i].keyFile))
		if err != nil {
			panic(err)
		}
		cert.OCSPStaple = testOCSPResponse
		cert.SignedCertificateTimestampList = testSCTList
		*testCerts[i].cert = cert
	}

	channelIDPEMBlock, err := ioutil.ReadFile(path.Join(*resourceDir, channelIDKeyFile))
	if err != nil {
		panic(err)
	}
	channelIDDERBlock, _ := pem.Decode(channelIDPEMBlock)
	if channelIDDERBlock.Type != "EC PRIVATE KEY" {
		panic("bad key type")
	}
	channelIDKey, err = x509.ParseECPrivateKey(channelIDDERBlock.Bytes)
	if err != nil {
		panic(err)
	}
	if channelIDKey.Curve != elliptic.P256() {
		panic("bad curve")
	}

	channelIDBytes = make([]byte, 64)
	writeIntPadded(channelIDBytes[:32], channelIDKey.X)
	writeIntPadded(channelIDBytes[32:], channelIDKey.Y)
}

func getRunnerCertificate(t testCert) Certificate {
	for _, cert := range testCerts {
		if cert.id == t {
			return *cert.cert
		}
	}
	panic("Unknown test certificate")
}

func getShimCertificate(t testCert) string {
	for _, cert := range testCerts {
		if cert.id == t {
			return cert.certFile
		}
	}
	panic("Unknown test certificate")
}

func getShimKey(t testCert) string {
	for _, cert := range testCerts {
		if cert.id == t {
			return cert.keyFile
		}
	}
	panic("Unknown test certificate")
}

type testType int

const (
	clientTest testType = iota
	serverTest
)

type protocol int

const (
	tls protocol = iota
	dtls
)

const (
	alpn = 1
	npn  = 2
)

type testCase struct {
	testType      testType
	protocol      protocol
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
	// expectedResumeVersion, if non-zero, specifies the TLS version that
	// must be negotiated on resumption. If zero, expectedVersion is used.
	expectedResumeVersion uint16
	// expectedCipher, if non-zero, specifies the TLS cipher suite that
	// should be negotiated.
	expectedCipher uint16
	// expectChannelID controls whether the connection should have
	// negotiated a Channel ID with channelIDKey.
	expectChannelID bool
	// expectedNextProto controls whether the connection should
	// negotiate a next protocol via NPN or ALPN.
	expectedNextProto string
	// expectNoNextProto, if true, means that no next protocol should be
	// negotiated.
	expectNoNextProto bool
	// expectedNextProtoType, if non-zero, is the expected next
	// protocol negotiation mechanism.
	expectedNextProtoType int
	// expectedSRTPProtectionProfile is the DTLS-SRTP profile that
	// should be negotiated. If zero, none should be negotiated.
	expectedSRTPProtectionProfile uint16
	// expectedOCSPResponse, if not nil, is the expected OCSP response to be received.
	expectedOCSPResponse []uint8
	// expectedSCTList, if not nil, is the expected SCT list to be received.
	expectedSCTList []uint8
	// expectedPeerSignatureAlgorithm, if not zero, is the signature
	// algorithm that the peer should have used in the handshake.
	expectedPeerSignatureAlgorithm signatureAlgorithm
	// expectedCurveID, if not zero, is the curve that the handshake should
	// have used.
	expectedCurveID CurveID
	// messageLen is the length, in bytes, of the test message that will be
	// sent.
	messageLen int
	// messageCount is the number of test messages that will be sent.
	messageCount int
	// certFile is the path to the certificate to use for the server.
	certFile string
	// keyFile is the path to the private key to use for the server.
	keyFile string
	// resumeSession controls whether a second connection should be tested
	// which attempts to resume the first session.
	resumeSession bool
	// expectResumeRejected, if true, specifies that the attempted
	// resumption must be rejected by the client. This is only valid for a
	// serverTest.
	expectResumeRejected bool
	// resumeConfig, if not nil, points to a Config to be used on
	// resumption. Unless newSessionsOnResume is set,
	// SessionTicketKey, ServerSessionCache, and
	// ClientSessionCache are copied from the initial connection's
	// config. If nil, the initial connection's config is used.
	resumeConfig *Config
	// newSessionsOnResume, if true, will cause resumeConfig to
	// use a different session resumption context.
	newSessionsOnResume bool
	// noSessionCache, if true, will cause the server to run without a
	// session cache.
	noSessionCache bool
	// sendPrefix sends a prefix on the socket before actually performing a
	// handshake.
	sendPrefix string
	// shimWritesFirst controls whether the shim sends an initial "hello"
	// message before doing a roundtrip with the runner.
	shimWritesFirst bool
	// shimShutsDown, if true, runs a test where the shim shuts down the
	// connection immediately after the handshake rather than echoing
	// messages from the runner.
	shimShutsDown bool
	// renegotiate indicates the number of times the connection should be
	// renegotiated during the exchange.
	renegotiate int
	// renegotiateCiphers is a list of ciphersuite ids that will be
	// switched in just before renegotiation.
	renegotiateCiphers []uint16
	// replayWrites, if true, configures the underlying transport
	// to replay every write it makes in DTLS tests.
	replayWrites bool
	// damageFirstWrite, if true, configures the underlying transport to
	// damage the final byte of the first application data write.
	damageFirstWrite bool
	// exportKeyingMaterial, if non-zero, configures the test to exchange
	// keying material and verify they match.
	exportKeyingMaterial int
	exportLabel          string
	exportContext        string
	useExportContext     bool
	// flags, if not empty, contains a list of command-line flags that will
	// be passed to the shim program.
	flags []string
	// testTLSUnique, if true, causes the shim to send the tls-unique value
	// which will be compared against the expected value.
	testTLSUnique bool
	// sendEmptyRecords is the number of consecutive empty records to send
	// before and after the test message.
	sendEmptyRecords int
	// sendWarningAlerts is the number of consecutive warning alerts to send
	// before and after the test message.
	sendWarningAlerts int
	// expectMessageDropped, if true, means the test message is expected to
	// be dropped by the client rather than echoed back.
	expectMessageDropped bool
}

var testCases []testCase

func writeTranscript(test *testCase, isResume bool, data []byte) {
	if len(data) == 0 {
		return
	}

	protocol := "tls"
	if test.protocol == dtls {
		protocol = "dtls"
	}

	side := "client"
	if test.testType == serverTest {
		side = "server"
	}

	dir := path.Join(*transcriptDir, protocol, side)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error making %s: %s\n", dir, err)
		return
	}

	name := test.name
	if isResume {
		name += "-Resume"
	} else {
		name += "-Normal"
	}

	if err := ioutil.WriteFile(path.Join(dir, name), data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %s\n", name, err)
	}
}

// A timeoutConn implements an idle timeout on each Read and Write operation.
type timeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (t *timeoutConn) Read(b []byte) (int, error) {
	if err := t.SetReadDeadline(time.Now().Add(t.timeout)); err != nil {
		return 0, err
	}
	return t.Conn.Read(b)
}

func (t *timeoutConn) Write(b []byte) (int, error) {
	if err := t.SetWriteDeadline(time.Now().Add(t.timeout)); err != nil {
		return 0, err
	}
	return t.Conn.Write(b)
}

func doExchange(test *testCase, config *Config, conn net.Conn, isResume bool) error {
	conn = &timeoutConn{conn, *idleTimeout}

	if test.protocol == dtls {
		config.Bugs.PacketAdaptor = newPacketAdaptor(conn)
		conn = config.Bugs.PacketAdaptor
	}

	if *flagDebug || len(*transcriptDir) != 0 {
		local, peer := "client", "server"
		if test.testType == clientTest {
			local, peer = peer, local
		}
		connDebug := &recordingConn{
			Conn:       conn,
			isDatagram: test.protocol == dtls,
			local:      local,
			peer:       peer,
		}
		conn = connDebug
		if *flagDebug {
			defer connDebug.WriteTo(os.Stdout)
		}
		if len(*transcriptDir) != 0 {
			defer func() {
				writeTranscript(test, isResume, connDebug.Transcript())
			}()
		}

		if config.Bugs.PacketAdaptor != nil {
			config.Bugs.PacketAdaptor.debug = connDebug
		}
	}

	if test.replayWrites {
		conn = newReplayAdaptor(conn)
	}

	var connDamage *damageAdaptor
	if test.damageFirstWrite {
		connDamage = newDamageAdaptor(conn)
		conn = connDamage
	}

	if test.sendPrefix != "" {
		if _, err := conn.Write([]byte(test.sendPrefix)); err != nil {
			return err
		}
	}

	var tlsConn *Conn
	if test.testType == clientTest {
		if test.protocol == dtls {
			tlsConn = DTLSServer(conn, config)
		} else {
			tlsConn = Server(conn, config)
		}
	} else {
		config.InsecureSkipVerify = true
		if test.protocol == dtls {
			tlsConn = DTLSClient(conn, config)
		} else {
			tlsConn = Client(conn, config)
		}
	}
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	// TODO(davidben): move all per-connection expectations into a dedicated
	// expectations struct that can be specified separately for the two
	// legs.
	expectedVersion := test.expectedVersion
	if isResume && test.expectedResumeVersion != 0 {
		expectedVersion = test.expectedResumeVersion
	}
	connState := tlsConn.ConnectionState()
	if vers := connState.Version; expectedVersion != 0 && vers != expectedVersion {
		return fmt.Errorf("got version %x, expected %x", vers, expectedVersion)
	}

	if cipher := connState.CipherSuite; test.expectedCipher != 0 && cipher != test.expectedCipher {
		return fmt.Errorf("got cipher %x, expected %x", cipher, test.expectedCipher)
	}
	if didResume := connState.DidResume; isResume && didResume == test.expectResumeRejected {
		return fmt.Errorf("didResume is %t, but we expected the opposite", didResume)
	}

	if test.expectChannelID {
		channelID := connState.ChannelID
		if channelID == nil {
			return fmt.Errorf("no channel ID negotiated")
		}
		if channelID.Curve != channelIDKey.Curve ||
			channelIDKey.X.Cmp(channelIDKey.X) != 0 ||
			channelIDKey.Y.Cmp(channelIDKey.Y) != 0 {
			return fmt.Errorf("incorrect channel ID")
		}
	}

	if expected := test.expectedNextProto; expected != "" {
		if actual := connState.NegotiatedProtocol; actual != expected {
			return fmt.Errorf("next proto mismatch: got %s, wanted %s", actual, expected)
		}
	}

	if test.expectNoNextProto {
		if actual := connState.NegotiatedProtocol; actual != "" {
			return fmt.Errorf("got unexpected next proto %s", actual)
		}
	}

	if test.expectedNextProtoType != 0 {
		if (test.expectedNextProtoType == alpn) != connState.NegotiatedProtocolFromALPN {
			return fmt.Errorf("next proto type mismatch")
		}
	}

	if p := connState.SRTPProtectionProfile; p != test.expectedSRTPProtectionProfile {
		return fmt.Errorf("SRTP profile mismatch: got %d, wanted %d", p, test.expectedSRTPProtectionProfile)
	}

	if test.expectedOCSPResponse != nil && !bytes.Equal(test.expectedOCSPResponse, tlsConn.OCSPResponse()) {
		return fmt.Errorf("OCSP Response mismatch: got %x, wanted %x", tlsConn.OCSPResponse(), test.expectedOCSPResponse)
	}

	if test.expectedSCTList != nil && !bytes.Equal(test.expectedSCTList, connState.SCTList) {
		return fmt.Errorf("SCT list mismatch")
	}

	if expected := test.expectedPeerSignatureAlgorithm; expected != 0 && expected != connState.PeerSignatureAlgorithm {
		return fmt.Errorf("expected peer to use signature algorithm %04x, but got %04x", expected, connState.PeerSignatureAlgorithm)
	}

	if expected := test.expectedCurveID; expected != 0 && expected != connState.CurveID {
		return fmt.Errorf("expected peer to use curve %04x, but got %04x", expected, connState.CurveID)
	}

	if test.exportKeyingMaterial > 0 {
		actual := make([]byte, test.exportKeyingMaterial)
		if _, err := io.ReadFull(tlsConn, actual); err != nil {
			return err
		}
		expected, err := tlsConn.ExportKeyingMaterial(test.exportKeyingMaterial, []byte(test.exportLabel), []byte(test.exportContext), test.useExportContext)
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, expected) {
			return fmt.Errorf("keying material mismatch")
		}
	}

	if test.testTLSUnique {
		var peersValue [12]byte
		if _, err := io.ReadFull(tlsConn, peersValue[:]); err != nil {
			return err
		}
		expected := tlsConn.ConnectionState().TLSUnique
		if !bytes.Equal(peersValue[:], expected) {
			return fmt.Errorf("tls-unique mismatch: peer sent %x, but %x was expected", peersValue[:], expected)
		}
	}

	if test.shimWritesFirst {
		var buf [5]byte
		_, err := io.ReadFull(tlsConn, buf[:])
		if err != nil {
			return err
		}
		if string(buf[:]) != "hello" {
			return fmt.Errorf("bad initial message")
		}
	}

	for i := 0; i < test.sendEmptyRecords; i++ {
		tlsConn.Write(nil)
	}

	for i := 0; i < test.sendWarningAlerts; i++ {
		tlsConn.SendAlert(alertLevelWarning, alertUnexpectedMessage)
	}

	if test.renegotiate > 0 {
		if test.renegotiateCiphers != nil {
			config.CipherSuites = test.renegotiateCiphers
		}
		for i := 0; i < test.renegotiate; i++ {
			if err := tlsConn.Renegotiate(); err != nil {
				return err
			}
		}
	} else if test.renegotiateCiphers != nil {
		panic("renegotiateCiphers without renegotiate")
	}

	if test.damageFirstWrite {
		connDamage.setDamage(true)
		tlsConn.Write([]byte("DAMAGED WRITE"))
		connDamage.setDamage(false)
	}

	messageLen := test.messageLen
	if messageLen < 0 {
		if test.protocol == dtls {
			return fmt.Errorf("messageLen < 0 not supported for DTLS tests")
		}
		// Read until EOF.
		_, err := io.Copy(ioutil.Discard, tlsConn)
		return err
	}
	if messageLen == 0 {
		messageLen = 32
	}

	messageCount := test.messageCount
	if messageCount == 0 {
		messageCount = 1
	}

	for j := 0; j < messageCount; j++ {
		testMessage := make([]byte, messageLen)
		for i := range testMessage {
			testMessage[i] = 0x42 ^ byte(j)
		}
		tlsConn.Write(testMessage)

		for i := 0; i < test.sendEmptyRecords; i++ {
			tlsConn.Write(nil)
		}

		for i := 0; i < test.sendWarningAlerts; i++ {
			tlsConn.SendAlert(alertLevelWarning, alertUnexpectedMessage)
		}

		if test.shimShutsDown || test.expectMessageDropped {
			// The shim will not respond.
			continue
		}

		buf := make([]byte, len(testMessage))
		if test.protocol == dtls {
			bufTmp := make([]byte, len(buf)+1)
			n, err := tlsConn.Read(bufTmp)
			if err != nil {
				return err
			}
			if n != len(buf) {
				return fmt.Errorf("bad reply; length mismatch (%d vs %d)", n, len(buf))
			}
			copy(buf, bufTmp)
		} else {
			_, err := io.ReadFull(tlsConn, buf)
			if err != nil {
				return err
			}
		}

		for i, v := range buf {
			if v != testMessage[i]^0xff {
				return fmt.Errorf("bad reply contents at byte %d", i)
			}
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

func lldbOf(path string, args ...string) *exec.Cmd {
	xtermArgs := []string{"-e", "lldb", "--"}
	xtermArgs = append(xtermArgs, path)
	xtermArgs = append(xtermArgs, args...)

	return exec.Command("xterm", xtermArgs...)
}

type moreMallocsError struct{}

func (moreMallocsError) Error() string {
	return "child process did not exhaust all allocation calls"
}

var errMoreMallocs = moreMallocsError{}

// accept accepts a connection from listener, unless waitChan signals a process
// exit first.
func acceptOrWait(listener net.Listener, waitChan chan error) (net.Conn, error) {
	type connOrError struct {
		conn net.Conn
		err  error
	}
	connChan := make(chan connOrError, 1)
	go func() {
		conn, err := listener.Accept()
		connChan <- connOrError{conn, err}
		close(connChan)
	}()
	select {
	case result := <-connChan:
		return result.conn, result.err
	case childErr := <-waitChan:
		waitChan <- childErr
		return nil, fmt.Errorf("child exited early: %s", childErr)
	}
}

func runTest(test *testCase, shimPath string, mallocNumToFail int64) error {
	if !test.shouldFail && (len(test.expectedError) > 0 || len(test.expectedLocalError) > 0) {
		panic("Error expected without shouldFail in " + test.name)
	}

	if test.expectResumeRejected && !test.resumeSession {
		panic("expectResumeRejected without resumeSession in " + test.name)
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		panic(err)
	}
	defer func() {
		if listener != nil {
			listener.Close()
		}
	}()

	flags := []string{"-port", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)}
	if test.testType == serverTest {
		flags = append(flags, "-server")

		flags = append(flags, "-key-file")
		if test.keyFile == "" {
			flags = append(flags, path.Join(*resourceDir, rsaKeyFile))
		} else {
			flags = append(flags, path.Join(*resourceDir, test.keyFile))
		}

		flags = append(flags, "-cert-file")
		if test.certFile == "" {
			flags = append(flags, path.Join(*resourceDir, rsaCertificateFile))
		} else {
			flags = append(flags, path.Join(*resourceDir, test.certFile))
		}
	}

	if test.protocol == dtls {
		flags = append(flags, "-dtls")
	}

	if test.resumeSession {
		flags = append(flags, "-resume")
	}

	if test.shimWritesFirst {
		flags = append(flags, "-shim-writes-first")
	}

	if test.shimShutsDown {
		flags = append(flags, "-shim-shuts-down")
	}

	if test.exportKeyingMaterial > 0 {
		flags = append(flags, "-export-keying-material", strconv.Itoa(test.exportKeyingMaterial))
		flags = append(flags, "-export-label", test.exportLabel)
		flags = append(flags, "-export-context", test.exportContext)
		if test.useExportContext {
			flags = append(flags, "-use-export-context")
		}
	}
	if test.expectResumeRejected {
		flags = append(flags, "-expect-session-miss")
	}

	if test.testTLSUnique {
		flags = append(flags, "-tls-unique")
	}

	flags = append(flags, test.flags...)

	var shim *exec.Cmd
	if *useValgrind {
		shim = valgrindOf(false, shimPath, flags...)
	} else if *useGDB {
		shim = gdbOf(shimPath, flags...)
	} else if *useLLDB {
		shim = lldbOf(shimPath, flags...)
	} else {
		shim = exec.Command(shimPath, flags...)
	}
	shim.Stdin = os.Stdin
	var stdoutBuf, stderrBuf bytes.Buffer
	shim.Stdout = &stdoutBuf
	shim.Stderr = &stderrBuf
	if mallocNumToFail >= 0 {
		shim.Env = os.Environ()
		shim.Env = append(shim.Env, "MALLOC_NUMBER_TO_FAIL="+strconv.FormatInt(mallocNumToFail, 10))
		if *mallocTestDebug {
			shim.Env = append(shim.Env, "MALLOC_BREAK_ON_FAIL=1")
		}
		shim.Env = append(shim.Env, "_MALLOC_CHECK=1")
	}

	if err := shim.Start(); err != nil {
		panic(err)
	}
	waitChan := make(chan error, 1)
	go func() { waitChan <- shim.Wait() }()

	config := test.config
	if !test.noSessionCache {
		config.ClientSessionCache = NewLRUClientSessionCache(1)
		config.ServerSessionCache = NewLRUServerSessionCache(1)
	}
	if test.testType == clientTest {
		if len(config.Certificates) == 0 {
			config.Certificates = []Certificate{rsaCertificate}
		}
	} else {
		// Supply a ServerName to ensure a constant session cache key,
		// rather than falling back to net.Conn.RemoteAddr.
		if len(config.ServerName) == 0 {
			config.ServerName = "test"
		}
	}
	if *fuzzer {
		config.Bugs.NullAllCiphers = true
	}
	if *deterministic {
		config.Rand = &deterministicRand{}
	}

	conn, err := acceptOrWait(listener, waitChan)
	if err == nil {
		err = doExchange(test, &config, conn, false /* not a resumption */)
		conn.Close()
	}

	if err == nil && test.resumeSession {
		var resumeConfig Config
		if test.resumeConfig != nil {
			resumeConfig = *test.resumeConfig
			if len(resumeConfig.ServerName) == 0 {
				resumeConfig.ServerName = config.ServerName
			}
			if len(resumeConfig.Certificates) == 0 {
				resumeConfig.Certificates = []Certificate{rsaCertificate}
			}
			if test.newSessionsOnResume {
				if !test.noSessionCache {
					resumeConfig.ClientSessionCache = NewLRUClientSessionCache(1)
					resumeConfig.ServerSessionCache = NewLRUServerSessionCache(1)
				}
			} else {
				resumeConfig.SessionTicketKey = config.SessionTicketKey
				resumeConfig.ClientSessionCache = config.ClientSessionCache
				resumeConfig.ServerSessionCache = config.ServerSessionCache
			}
			if *fuzzer {
				resumeConfig.Bugs.NullAllCiphers = true
			}
			resumeConfig.Rand = config.Rand
		} else {
			resumeConfig = config
		}
		var connResume net.Conn
		connResume, err = acceptOrWait(listener, waitChan)
		if err == nil {
			err = doExchange(test, &resumeConfig, connResume, true /* resumption */)
			connResume.Close()
		}
	}

	// Close the listener now. This is to avoid hangs should the shim try to
	// open more connections than expected.
	listener.Close()
	listener = nil

	childErr := <-waitChan
	if exitError, ok := childErr.(*exec.ExitError); ok {
		if exitError.Sys().(syscall.WaitStatus).ExitStatus() == 88 {
			return errMoreMallocs
		}
	}

	// Account for Windows line endings.
	stdout := strings.Replace(string(stdoutBuf.Bytes()), "\r\n", "\n", -1)
	stderr := strings.Replace(string(stderrBuf.Bytes()), "\r\n", "\n", -1)

	// Separate the errors from the shim and those from tools like
	// AddressSanitizer.
	var extraStderr string
	if stderrParts := strings.SplitN(stderr, "--- DONE ---\n", 2); len(stderrParts) == 2 {
		stderr = stderrParts[0]
		extraStderr = stderrParts[1]
	}

	failed := err != nil || childErr != nil
	correctFailure := len(test.expectedError) == 0 || strings.Contains(stderr, test.expectedError)
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

		return fmt.Errorf("%s: local error '%s', child error '%s', stdout:\n%s\nstderr:\n%s", msg, localError, childError, stdout, stderr)
	}

	if !*useValgrind && (len(extraStderr) > 0 || (!failed && len(stderr) > 0)) {
		return fmt.Errorf("unexpected error output:\n%s\n%s", stderr, extraStderr)
	}

	return nil
}

var tlsVersions = []struct {
	name    string
	version uint16
	flag    string
	hasDTLS bool
}{
	{"SSL3", VersionSSL30, "-no-ssl3", false},
	{"TLS1", VersionTLS10, "-no-tls1", true},
	{"TLS11", VersionTLS11, "-no-tls11", false},
	{"TLS12", VersionTLS12, "-no-tls12", true},
	{"TLS13", VersionTLS13, "-no-tls13", false},
}

var testCipherSuites = []struct {
	name string
	id   uint16
}{
	{"3DES-SHA", TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	{"AES128-GCM", TLS_RSA_WITH_AES_128_GCM_SHA256},
	{"AES128-SHA", TLS_RSA_WITH_AES_128_CBC_SHA},
	{"AES128-SHA256", TLS_RSA_WITH_AES_128_CBC_SHA256},
	{"AES256-GCM", TLS_RSA_WITH_AES_256_GCM_SHA384},
	{"AES256-SHA", TLS_RSA_WITH_AES_256_CBC_SHA},
	{"AES256-SHA256", TLS_RSA_WITH_AES_256_CBC_SHA256},
	{"DHE-RSA-AES128-GCM", TLS_DHE_RSA_WITH_AES_128_GCM_SHA256},
	{"DHE-RSA-AES128-SHA", TLS_DHE_RSA_WITH_AES_128_CBC_SHA},
	{"DHE-RSA-AES128-SHA256", TLS_DHE_RSA_WITH_AES_128_CBC_SHA256},
	{"DHE-RSA-AES256-GCM", TLS_DHE_RSA_WITH_AES_256_GCM_SHA384},
	{"DHE-RSA-AES256-SHA", TLS_DHE_RSA_WITH_AES_256_CBC_SHA},
	{"DHE-RSA-AES256-SHA256", TLS_DHE_RSA_WITH_AES_256_CBC_SHA256},
	{"ECDHE-ECDSA-AES128-GCM", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	{"ECDHE-ECDSA-AES128-SHA", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
	{"ECDHE-ECDSA-AES128-SHA256", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256},
	{"ECDHE-ECDSA-AES256-GCM", TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
	{"ECDHE-ECDSA-AES256-SHA", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
	{"ECDHE-ECDSA-AES256-SHA384", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384},
	{"ECDHE-ECDSA-CHACHA20-POLY1305", TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
	{"ECDHE-ECDSA-CHACHA20-POLY1305-OLD", TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD},
	{"ECDHE-ECDSA-RC4-SHA", TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
	{"ECDHE-RSA-AES128-GCM", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	{"ECDHE-RSA-AES128-SHA", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
	{"ECDHE-RSA-AES128-SHA256", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256},
	{"ECDHE-RSA-AES256-GCM", TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	{"ECDHE-RSA-AES256-SHA", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
	{"ECDHE-RSA-AES256-SHA384", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384},
	{"ECDHE-RSA-CHACHA20-POLY1305", TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
	{"ECDHE-RSA-CHACHA20-POLY1305-OLD", TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD},
	{"ECDHE-RSA-RC4-SHA", TLS_ECDHE_RSA_WITH_RC4_128_SHA},
	{"CECPQ1-RSA-CHACHA20-POLY1305-SHA256", TLS_CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256},
	{"CECPQ1-ECDSA-CHACHA20-POLY1305-SHA256", TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
	{"CECPQ1-RSA-AES256-GCM-SHA384", TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384},
	{"CECPQ1-ECDSA-AES256-GCM-SHA384", TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384},
	{"PSK-AES128-CBC-SHA", TLS_PSK_WITH_AES_128_CBC_SHA},
	{"PSK-AES256-CBC-SHA", TLS_PSK_WITH_AES_256_CBC_SHA},
	{"ECDHE-PSK-AES128-CBC-SHA", TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA},
	{"ECDHE-PSK-AES256-CBC-SHA", TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA},
	{"ECDHE-PSK-CHACHA20-POLY1305", TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256},
	{"ECDHE-PSK-AES128-GCM-SHA256", TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256},
	{"ECDHE-PSK-AES256-GCM-SHA384", TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384},
	{"PSK-RC4-SHA", TLS_PSK_WITH_RC4_128_SHA},
	{"RC4-MD5", TLS_RSA_WITH_RC4_128_MD5},
	{"RC4-SHA", TLS_RSA_WITH_RC4_128_SHA},
	{"NULL-SHA", TLS_RSA_WITH_NULL_SHA},
}

func hasComponent(suiteName, component string) bool {
	return strings.Contains("-"+suiteName+"-", "-"+component+"-")
}

func isTLS12Only(suiteName string) bool {
	return hasComponent(suiteName, "GCM") ||
		hasComponent(suiteName, "SHA256") ||
		hasComponent(suiteName, "SHA384") ||
		hasComponent(suiteName, "POLY1305")
}

func isTLS13Suite(suiteName string) bool {
	// Only AEADs.
	if !hasComponent(suiteName, "GCM") && !hasComponent(suiteName, "POLY1305") {
		return false
	}
	// No old CHACHA20_POLY1305.
	if hasComponent(suiteName, "CHACHA20-POLY1305-OLD") {
		return false
	}
	// Must have ECDHE.
	// TODO(davidben,svaldez): Add pure PSK support.
	if !hasComponent(suiteName, "ECDHE") {
		return false
	}
	// TODO(davidben,svaldez): Add PSK support.
	if hasComponent(suiteName, "PSK") {
		return false
	}
	return true
}

func isDTLSCipher(suiteName string) bool {
	return !hasComponent(suiteName, "RC4") && !hasComponent(suiteName, "NULL")
}

func bigFromHex(hex string) *big.Int {
	ret, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("failed to parse hex number 0x" + hex)
	}
	return ret
}

func addBasicTests() {
	basicTests := []testCase{
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
			name: "SendFallbackSCSV",
			config: Config{
				Bugs: ProtocolBugs{
					FailIfNotFallbackSCSV: true,
				},
			},
			flags: []string{"-fallback-scsv"},
		},
		{
			name: "ClientCertificateTypes",
			config: Config{
				MaxVersion: VersionTLS12,
				ClientAuth: RequestClientCert,
				ClientCertificateTypes: []byte{
					CertTypeDSSSign,
					CertTypeRSASign,
					CertTypeECDSASign,
				},
			},
			flags: []string{
				"-expect-certificate-types",
				base64.StdEncoding.EncodeToString([]byte{
					CertTypeDSSSign,
					CertTypeRSASign,
					CertTypeECDSASign,
				}),
			},
		},
		{
			name: "UnauthenticatedECDH",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				Bugs: ProtocolBugs{
					UnauthenticatedECDH: true,
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_MESSAGE:",
		},
		{
			name: "SkipCertificateStatus",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				Bugs: ProtocolBugs{
					SkipCertificateStatus: true,
				},
			},
			flags: []string{
				"-enable-ocsp-stapling",
			},
		},
		{
			name: "SkipServerKeyExchange",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				Bugs: ProtocolBugs{
					SkipServerKeyExchange: true,
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_MESSAGE:",
		},
		{
			testType: serverTest,
			name:     "Alert",
			config: Config{
				Bugs: ProtocolBugs{
					SendSpuriousAlert: alertRecordOverflow,
				},
			},
			shouldFail:    true,
			expectedError: ":TLSV1_ALERT_RECORD_OVERFLOW:",
		},
		{
			protocol: dtls,
			testType: serverTest,
			name:     "Alert-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					SendSpuriousAlert: alertRecordOverflow,
				},
			},
			shouldFail:    true,
			expectedError: ":TLSV1_ALERT_RECORD_OVERFLOW:",
		},
		{
			testType: serverTest,
			name:     "FragmentAlert",
			config: Config{
				Bugs: ProtocolBugs{
					FragmentAlert:     true,
					SendSpuriousAlert: alertRecordOverflow,
				},
			},
			shouldFail:    true,
			expectedError: ":BAD_ALERT:",
		},
		{
			protocol: dtls,
			testType: serverTest,
			name:     "FragmentAlert-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					FragmentAlert:     true,
					SendSpuriousAlert: alertRecordOverflow,
				},
			},
			shouldFail:    true,
			expectedError: ":BAD_ALERT:",
		},
		{
			testType: serverTest,
			name:     "DoubleAlert",
			config: Config{
				Bugs: ProtocolBugs{
					DoubleAlert:       true,
					SendSpuriousAlert: alertRecordOverflow,
				},
			},
			shouldFail:    true,
			expectedError: ":BAD_ALERT:",
		},
		{
			protocol: dtls,
			testType: serverTest,
			name:     "DoubleAlert-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					DoubleAlert:       true,
					SendSpuriousAlert: alertRecordOverflow,
				},
			},
			shouldFail:    true,
			expectedError: ":BAD_ALERT:",
		},
		{
			name: "SkipNewSessionTicket",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SkipNewSessionTicket: true,
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
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
		{
			testType: serverTest,
			name:     "FallbackSCSV-VersionMatch-TLS12",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendFallbackSCSV: true,
				},
			},
			flags: []string{"-max-version", strconv.Itoa(VersionTLS12)},
		},
		{
			testType: serverTest,
			name:     "FragmentedClientVersion",
			config: Config{
				Bugs: ProtocolBugs{
					MaxHandshakeRecordLength: 1,
					FragmentClientVersion:    true,
				},
			},
			expectedVersion: VersionTLS13,
		},
		{
			testType:      serverTest,
			name:          "HttpGET",
			sendPrefix:    "GET / HTTP/1.0\n",
			shouldFail:    true,
			expectedError: ":HTTP_REQUEST:",
		},
		{
			testType:      serverTest,
			name:          "HttpPOST",
			sendPrefix:    "POST / HTTP/1.0\n",
			shouldFail:    true,
			expectedError: ":HTTP_REQUEST:",
		},
		{
			testType:      serverTest,
			name:          "HttpHEAD",
			sendPrefix:    "HEAD / HTTP/1.0\n",
			shouldFail:    true,
			expectedError: ":HTTP_REQUEST:",
		},
		{
			testType:      serverTest,
			name:          "HttpPUT",
			sendPrefix:    "PUT / HTTP/1.0\n",
			shouldFail:    true,
			expectedError: ":HTTP_REQUEST:",
		},
		{
			testType:      serverTest,
			name:          "HttpCONNECT",
			sendPrefix:    "CONNECT www.google.com:443 HTTP/1.0\n",
			shouldFail:    true,
			expectedError: ":HTTPS_PROXY_REQUEST:",
		},
		{
			testType:      serverTest,
			name:          "Garbage",
			sendPrefix:    "blah",
			shouldFail:    true,
			expectedError: ":WRONG_VERSION_NUMBER:",
		},
		{
			name: "RSAEphemeralKey",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_RSA_WITH_AES_128_CBC_SHA},
				Bugs: ProtocolBugs{
					RSAEphemeralKey: true,
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_MESSAGE:",
		},
		{
			name:          "DisableEverything",
			flags:         []string{"-no-tls13", "-no-tls12", "-no-tls11", "-no-tls1", "-no-ssl3"},
			shouldFail:    true,
			expectedError: ":WRONG_SSL_VERSION:",
		},
		{
			protocol:      dtls,
			name:          "DisableEverything-DTLS",
			flags:         []string{"-no-tls12", "-no-tls1"},
			shouldFail:    true,
			expectedError: ":WRONG_SSL_VERSION:",
		},
		{
			protocol: dtls,
			testType: serverTest,
			name:     "MTU",
			config: Config{
				Bugs: ProtocolBugs{
					MaxPacketLength: 256,
				},
			},
			flags: []string{"-mtu", "256"},
		},
		{
			protocol: dtls,
			testType: serverTest,
			name:     "MTUExceeded",
			config: Config{
				Bugs: ProtocolBugs{
					MaxPacketLength: 255,
				},
			},
			flags:              []string{"-mtu", "256"},
			shouldFail:         true,
			expectedLocalError: "dtls: exceeded maximum packet length",
		},
		{
			name: "CertMismatchRSA",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				Certificates: []Certificate{ecdsaP256Certificate},
				Bugs: ProtocolBugs{
					SendCipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			},
			shouldFail:    true,
			expectedError: ":WRONG_CERTIFICATE_TYPE:",
		},
		{
			name: "CertMismatchRSA-TLS13",
			config: Config{
				MaxVersion:   VersionTLS13,
				CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				Certificates: []Certificate{ecdsaP256Certificate},
				Bugs: ProtocolBugs{
					SendCipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			},
			shouldFail:    true,
			expectedError: ":WRONG_CERTIFICATE_TYPE:",
		},
		{
			name: "CertMismatchECDSA",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				Certificates: []Certificate{rsaCertificate},
				Bugs: ProtocolBugs{
					SendCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
			},
			shouldFail:    true,
			expectedError: ":WRONG_CERTIFICATE_TYPE:",
		},
		{
			name: "CertMismatchECDSA-TLS13",
			config: Config{
				MaxVersion:   VersionTLS13,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				Certificates: []Certificate{rsaCertificate},
				Bugs: ProtocolBugs{
					SendCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
			},
			shouldFail:    true,
			expectedError: ":WRONG_CERTIFICATE_TYPE:",
		},
		{
			name: "EmptyCertificateList",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				Bugs: ProtocolBugs{
					EmptyCertificateList: true,
				},
			},
			shouldFail:    true,
			expectedError: ":DECODE_ERROR:",
		},
		{
			name: "EmptyCertificateList-TLS13",
			config: Config{
				MaxVersion:   VersionTLS13,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				Bugs: ProtocolBugs{
					EmptyCertificateList: true,
				},
			},
			shouldFail:    true,
			expectedError: ":DECODE_ERROR:",
		},
		{
			name:             "TLSFatalBadPackets",
			damageFirstWrite: true,
			shouldFail:       true,
			expectedError:    ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
		},
		{
			protocol:         dtls,
			name:             "DTLSIgnoreBadPackets",
			damageFirstWrite: true,
		},
		{
			protocol:         dtls,
			name:             "DTLSIgnoreBadPackets-Async",
			damageFirstWrite: true,
			flags:            []string{"-async"},
		},
		{
			name: "AppDataBeforeHandshake",
			config: Config{
				Bugs: ProtocolBugs{
					AppDataBeforeHandshake: []byte("TEST MESSAGE"),
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		},
		{
			name: "AppDataBeforeHandshake-Empty",
			config: Config{
				Bugs: ProtocolBugs{
					AppDataBeforeHandshake: []byte{},
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		},
		{
			protocol: dtls,
			name:     "AppDataBeforeHandshake-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					AppDataBeforeHandshake: []byte("TEST MESSAGE"),
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		},
		{
			protocol: dtls,
			name:     "AppDataBeforeHandshake-DTLS-Empty",
			config: Config{
				Bugs: ProtocolBugs{
					AppDataBeforeHandshake: []byte{},
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		},
		{
			name: "AppDataAfterChangeCipherSpec",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					AppDataAfterChangeCipherSpec: []byte("TEST MESSAGE"),
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		},
		{
			name: "AppDataAfterChangeCipherSpec-Empty",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					AppDataAfterChangeCipherSpec: []byte{},
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		},
		{
			protocol: dtls,
			name:     "AppDataAfterChangeCipherSpec-DTLS",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					AppDataAfterChangeCipherSpec: []byte("TEST MESSAGE"),
				},
			},
			// BoringSSL's DTLS implementation will drop the out-of-order
			// application data.
		},
		{
			protocol: dtls,
			name:     "AppDataAfterChangeCipherSpec-DTLS-Empty",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					AppDataAfterChangeCipherSpec: []byte{},
				},
			},
			// BoringSSL's DTLS implementation will drop the out-of-order
			// application data.
		},
		{
			name: "AlertAfterChangeCipherSpec",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					AlertAfterChangeCipherSpec: alertRecordOverflow,
				},
			},
			shouldFail:    true,
			expectedError: ":TLSV1_ALERT_RECORD_OVERFLOW:",
		},
		{
			protocol: dtls,
			name:     "AlertAfterChangeCipherSpec-DTLS",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					AlertAfterChangeCipherSpec: alertRecordOverflow,
				},
			},
			shouldFail:    true,
			expectedError: ":TLSV1_ALERT_RECORD_OVERFLOW:",
		},
		{
			protocol: dtls,
			name:     "ReorderHandshakeFragments-Small-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					ReorderHandshakeFragments: true,
					// Small enough that every handshake message is
					// fragmented.
					MaxHandshakeRecordLength: 2,
				},
			},
		},
		{
			protocol: dtls,
			name:     "ReorderHandshakeFragments-Large-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					ReorderHandshakeFragments: true,
					// Large enough that no handshake message is
					// fragmented.
					MaxHandshakeRecordLength: 2048,
				},
			},
		},
		{
			protocol: dtls,
			name:     "MixCompleteMessageWithFragments-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					ReorderHandshakeFragments:       true,
					MixCompleteMessageWithFragments: true,
					MaxHandshakeRecordLength:        2,
				},
			},
		},
		{
			name: "SendInvalidRecordType",
			config: Config{
				Bugs: ProtocolBugs{
					SendInvalidRecordType: true,
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		},
		{
			protocol: dtls,
			name:     "SendInvalidRecordType-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					SendInvalidRecordType: true,
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		},
		{
			name: "FalseStart-SkipServerSecondLeg",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					SkipNewSessionTicket: true,
					SkipChangeCipherSpec: true,
					SkipFinished:         true,
					ExpectFalseStart:     true,
				},
			},
			flags: []string{
				"-false-start",
				"-handshake-never-done",
				"-advertise-alpn", "\x03foo",
			},
			shimWritesFirst: true,
			shouldFail:      true,
			expectedError:   ":UNEXPECTED_RECORD:",
		},
		{
			name: "FalseStart-SkipServerSecondLeg-Implicit",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					SkipNewSessionTicket: true,
					SkipChangeCipherSpec: true,
					SkipFinished:         true,
				},
			},
			flags: []string{
				"-implicit-handshake",
				"-false-start",
				"-handshake-never-done",
				"-advertise-alpn", "\x03foo",
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		},
		{
			testType:           serverTest,
			name:               "FailEarlyCallback",
			flags:              []string{"-fail-early-callback"},
			shouldFail:         true,
			expectedError:      ":CONNECTION_REJECTED:",
			expectedLocalError: "remote error: access denied",
		},
		{
			protocol: dtls,
			name:     "FragmentMessageTypeMismatch-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					MaxHandshakeRecordLength:    2,
					FragmentMessageTypeMismatch: true,
				},
			},
			shouldFail:    true,
			expectedError: ":FRAGMENT_MISMATCH:",
		},
		{
			protocol: dtls,
			name:     "FragmentMessageLengthMismatch-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					MaxHandshakeRecordLength:      2,
					FragmentMessageLengthMismatch: true,
				},
			},
			shouldFail:    true,
			expectedError: ":FRAGMENT_MISMATCH:",
		},
		{
			protocol: dtls,
			name:     "SplitFragments-Header-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					SplitFragments: 2,
				},
			},
			shouldFail:    true,
			expectedError: ":BAD_HANDSHAKE_RECORD:",
		},
		{
			protocol: dtls,
			name:     "SplitFragments-Boundary-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					SplitFragments: dtlsRecordHeaderLen,
				},
			},
			shouldFail:    true,
			expectedError: ":BAD_HANDSHAKE_RECORD:",
		},
		{
			protocol: dtls,
			name:     "SplitFragments-Body-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					SplitFragments: dtlsRecordHeaderLen + 1,
				},
			},
			shouldFail:    true,
			expectedError: ":BAD_HANDSHAKE_RECORD:",
		},
		{
			protocol: dtls,
			name:     "SendEmptyFragments-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					SendEmptyFragments: true,
				},
			},
		},
		{
			name: "BadFinished-Client",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					BadFinished: true,
				},
			},
			shouldFail:    true,
			expectedError: ":DIGEST_CHECK_FAILED:",
		},
		{
			name: "BadFinished-Client-TLS13",
			config: Config{
				MaxVersion: VersionTLS13,
				Bugs: ProtocolBugs{
					BadFinished: true,
				},
			},
			shouldFail:    true,
			expectedError: ":DIGEST_CHECK_FAILED:",
		},
		{
			testType: serverTest,
			name:     "BadFinished-Server",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					BadFinished: true,
				},
			},
			shouldFail:    true,
			expectedError: ":DIGEST_CHECK_FAILED:",
		},
		{
			testType: serverTest,
			name:     "BadFinished-Server-TLS13",
			config: Config{
				MaxVersion: VersionTLS13,
				Bugs: ProtocolBugs{
					BadFinished: true,
				},
			},
			shouldFail:    true,
			expectedError: ":DIGEST_CHECK_FAILED:",
		},
		{
			name: "FalseStart-BadFinished",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					BadFinished:      true,
					ExpectFalseStart: true,
				},
			},
			flags: []string{
				"-false-start",
				"-handshake-never-done",
				"-advertise-alpn", "\x03foo",
			},
			shimWritesFirst: true,
			shouldFail:      true,
			expectedError:   ":DIGEST_CHECK_FAILED:",
		},
		{
			name: "NoFalseStart-NoALPN",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				Bugs: ProtocolBugs{
					ExpectFalseStart:          true,
					AlertBeforeFalseStartTest: alertAccessDenied,
				},
			},
			flags: []string{
				"-false-start",
			},
			shimWritesFirst:    true,
			shouldFail:         true,
			expectedError:      ":TLSV1_ALERT_ACCESS_DENIED:",
			expectedLocalError: "tls: peer did not false start: EOF",
		},
		{
			name: "NoFalseStart-NoAEAD",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					ExpectFalseStart:          true,
					AlertBeforeFalseStartTest: alertAccessDenied,
				},
			},
			flags: []string{
				"-false-start",
				"-advertise-alpn", "\x03foo",
			},
			shimWritesFirst:    true,
			shouldFail:         true,
			expectedError:      ":TLSV1_ALERT_ACCESS_DENIED:",
			expectedLocalError: "tls: peer did not false start: EOF",
		},
		{
			name: "NoFalseStart-RSA",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					ExpectFalseStart:          true,
					AlertBeforeFalseStartTest: alertAccessDenied,
				},
			},
			flags: []string{
				"-false-start",
				"-advertise-alpn", "\x03foo",
			},
			shimWritesFirst:    true,
			shouldFail:         true,
			expectedError:      ":TLSV1_ALERT_ACCESS_DENIED:",
			expectedLocalError: "tls: peer did not false start: EOF",
		},
		{
			name: "NoFalseStart-DHE_RSA",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					ExpectFalseStart:          true,
					AlertBeforeFalseStartTest: alertAccessDenied,
				},
			},
			flags: []string{
				"-false-start",
				"-advertise-alpn", "\x03foo",
			},
			shimWritesFirst:    true,
			shouldFail:         true,
			expectedError:      ":TLSV1_ALERT_ACCESS_DENIED:",
			expectedLocalError: "tls: peer did not false start: EOF",
		},
		{
			protocol: dtls,
			name:     "SendSplitAlert-Sync",
			config: Config{
				Bugs: ProtocolBugs{
					SendSplitAlert: true,
				},
			},
		},
		{
			protocol: dtls,
			name:     "SendSplitAlert-Async",
			config: Config{
				Bugs: ProtocolBugs{
					SendSplitAlert: true,
				},
			},
			flags: []string{"-async"},
		},
		{
			protocol: dtls,
			name:     "PackDTLSHandshake",
			config: Config{
				Bugs: ProtocolBugs{
					MaxHandshakeRecordLength: 2,
					PackHandshakeFragments:   20,
					PackHandshakeRecords:     200,
				},
			},
		},
		{
			name:             "SendEmptyRecords-Pass",
			sendEmptyRecords: 32,
		},
		{
			name:             "SendEmptyRecords",
			sendEmptyRecords: 33,
			shouldFail:       true,
			expectedError:    ":TOO_MANY_EMPTY_FRAGMENTS:",
		},
		{
			name:             "SendEmptyRecords-Async",
			sendEmptyRecords: 33,
			flags:            []string{"-async"},
			shouldFail:       true,
			expectedError:    ":TOO_MANY_EMPTY_FRAGMENTS:",
		},
		{
			name:              "SendWarningAlerts-Pass",
			sendWarningAlerts: 4,
		},
		{
			protocol:          dtls,
			name:              "SendWarningAlerts-DTLS-Pass",
			sendWarningAlerts: 4,
		},
		{
			name:              "SendWarningAlerts",
			sendWarningAlerts: 5,
			shouldFail:        true,
			expectedError:     ":TOO_MANY_WARNING_ALERTS:",
		},
		{
			name:              "SendWarningAlerts-Async",
			sendWarningAlerts: 5,
			flags:             []string{"-async"},
			shouldFail:        true,
			expectedError:     ":TOO_MANY_WARNING_ALERTS:",
		},
		{
			name: "EmptySessionID",
			config: Config{
				MaxVersion:             VersionTLS12,
				SessionTicketsDisabled: true,
			},
			noSessionCache: true,
			flags:          []string{"-expect-no-session"},
		},
		{
			name: "Unclean-Shutdown",
			config: Config{
				Bugs: ProtocolBugs{
					NoCloseNotify:     true,
					ExpectCloseNotify: true,
				},
			},
			shimShutsDown: true,
			flags:         []string{"-check-close-notify"},
			shouldFail:    true,
			expectedError: "Unexpected SSL_shutdown result: -1 != 1",
		},
		{
			name: "Unclean-Shutdown-Ignored",
			config: Config{
				Bugs: ProtocolBugs{
					NoCloseNotify: true,
				},
			},
			shimShutsDown: true,
		},
		{
			name: "Unclean-Shutdown-Alert",
			config: Config{
				Bugs: ProtocolBugs{
					SendAlertOnShutdown: alertDecompressionFailure,
					ExpectCloseNotify:   true,
				},
			},
			shimShutsDown: true,
			flags:         []string{"-check-close-notify"},
			shouldFail:    true,
			expectedError: ":SSLV3_ALERT_DECOMPRESSION_FAILURE:",
		},
		{
			name: "LargePlaintext",
			config: Config{
				Bugs: ProtocolBugs{
					SendLargeRecords: true,
				},
			},
			messageLen:    maxPlaintext + 1,
			shouldFail:    true,
			expectedError: ":DATA_LENGTH_TOO_LONG:",
		},
		{
			protocol: dtls,
			name:     "LargePlaintext-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					SendLargeRecords: true,
				},
			},
			messageLen:    maxPlaintext + 1,
			shouldFail:    true,
			expectedError: ":DATA_LENGTH_TOO_LONG:",
		},
		{
			name: "LargeCiphertext",
			config: Config{
				Bugs: ProtocolBugs{
					SendLargeRecords: true,
				},
			},
			messageLen:    maxPlaintext * 2,
			shouldFail:    true,
			expectedError: ":ENCRYPTED_LENGTH_TOO_LONG:",
		},
		{
			protocol: dtls,
			name:     "LargeCiphertext-DTLS",
			config: Config{
				Bugs: ProtocolBugs{
					SendLargeRecords: true,
				},
			},
			messageLen: maxPlaintext * 2,
			// Unlike the other four cases, DTLS drops records which
			// are invalid before authentication, so the connection
			// does not fail.
			expectMessageDropped: true,
		},
		{
			// In TLS 1.2 and below, empty NewSessionTicket messages
			// mean the server changed its mind on sending a ticket.
			name: "SendEmptySessionTicket",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendEmptySessionTicket: true,
					FailIfSessionOffered:   true,
				},
			},
			flags:                []string{"-expect-no-session"},
			resumeSession:        true,
			expectResumeRejected: true,
		},
		{
			name:        "BadHelloRequest-1",
			renegotiate: 1,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					BadHelloRequest: []byte{typeHelloRequest, 0, 0, 1, 1},
				},
			},
			flags: []string{
				"-renegotiate-freely",
				"-expect-total-renegotiations", "1",
			},
			shouldFail:    true,
			expectedError: ":BAD_HELLO_REQUEST:",
		},
		{
			name:        "BadHelloRequest-2",
			renegotiate: 1,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					BadHelloRequest: []byte{typeServerKeyExchange, 0, 0, 0},
				},
			},
			flags: []string{
				"-renegotiate-freely",
				"-expect-total-renegotiations", "1",
			},
			shouldFail:    true,
			expectedError: ":BAD_HELLO_REQUEST:",
		},
		{
			testType: serverTest,
			name:     "SupportTicketsWithSessionID",
			config: Config{
				MaxVersion:             VersionTLS12,
				SessionTicketsDisabled: true,
			},
			resumeConfig: &Config{
				MaxVersion: VersionTLS12,
			},
			resumeSession: true,
		},
	}
	testCases = append(testCases, basicTests...)
}

func addCipherSuiteTests() {
	const bogusCipher = 0xfe00

	for _, suite := range testCipherSuites {
		const psk = "12345"
		const pskIdentity = "luggage combo"

		var cert Certificate
		var certFile string
		var keyFile string
		if hasComponent(suite.name, "ECDSA") {
			cert = ecdsaP256Certificate
			certFile = ecdsaP256CertificateFile
			keyFile = ecdsaP256KeyFile
		} else {
			cert = rsaCertificate
			certFile = rsaCertificateFile
			keyFile = rsaKeyFile
		}

		var flags []string
		if hasComponent(suite.name, "PSK") {
			flags = append(flags,
				"-psk", psk,
				"-psk-identity", pskIdentity)
		}
		if hasComponent(suite.name, "NULL") {
			// NULL ciphers must be explicitly enabled.
			flags = append(flags, "-cipher", "DEFAULT:NULL-SHA")
		}
		if hasComponent(suite.name, "CECPQ1") {
			// CECPQ1 ciphers must be explicitly enabled.
			flags = append(flags, "-cipher", "DEFAULT:kCECPQ1")
		}

		for _, ver := range tlsVersions {
			for _, protocol := range []protocol{tls, dtls} {
				var prefix string
				if protocol == dtls {
					if !ver.hasDTLS {
						continue
					}
					prefix = "D"
				}

				var shouldServerFail, shouldClientFail bool
				if hasComponent(suite.name, "ECDHE") && ver.version == VersionSSL30 {
					// BoringSSL clients accept ECDHE on SSLv3, but
					// a BoringSSL server will never select it
					// because the extension is missing.
					shouldServerFail = true
				}
				if isTLS12Only(suite.name) && ver.version < VersionTLS12 {
					shouldClientFail = true
					shouldServerFail = true
				}
				if !isTLS13Suite(suite.name) && ver.version >= VersionTLS13 {
					shouldClientFail = true
					shouldServerFail = true
				}
				if !isDTLSCipher(suite.name) && protocol == dtls {
					shouldClientFail = true
					shouldServerFail = true
				}

				var expectedServerError, expectedClientError string
				if shouldServerFail {
					expectedServerError = ":NO_SHARED_CIPHER:"
				}
				if shouldClientFail {
					expectedClientError = ":WRONG_CIPHER_RETURNED:"
				}

				// TODO(davidben,svaldez): Implement resumption for TLS 1.3.
				resumeSession := ver.version < VersionTLS13

				testCases = append(testCases, testCase{
					testType: serverTest,
					protocol: protocol,

					name: prefix + ver.name + "-" + suite.name + "-server",
					config: Config{
						MinVersion:           ver.version,
						MaxVersion:           ver.version,
						CipherSuites:         []uint16{suite.id},
						Certificates:         []Certificate{cert},
						PreSharedKey:         []byte(psk),
						PreSharedKeyIdentity: pskIdentity,
						Bugs: ProtocolBugs{
							EnableAllCiphers:            shouldServerFail,
							IgnorePeerCipherPreferences: shouldServerFail,
						},
					},
					certFile:      certFile,
					keyFile:       keyFile,
					flags:         flags,
					resumeSession: resumeSession,
					shouldFail:    shouldServerFail,
					expectedError: expectedServerError,
				})

				testCases = append(testCases, testCase{
					testType: clientTest,
					protocol: protocol,
					name:     prefix + ver.name + "-" + suite.name + "-client",
					config: Config{
						MinVersion:           ver.version,
						MaxVersion:           ver.version,
						CipherSuites:         []uint16{suite.id},
						Certificates:         []Certificate{cert},
						PreSharedKey:         []byte(psk),
						PreSharedKeyIdentity: pskIdentity,
						Bugs: ProtocolBugs{
							EnableAllCiphers:            shouldClientFail,
							IgnorePeerCipherPreferences: shouldClientFail,
						},
					},
					flags:         flags,
					resumeSession: resumeSession,
					shouldFail:    shouldClientFail,
					expectedError: expectedClientError,
				})

				if !shouldClientFail {
					// Ensure the maximum record size is accepted.
					testCases = append(testCases, testCase{
						name: prefix + ver.name + "-" + suite.name + "-LargeRecord",
						config: Config{
							MinVersion:           ver.version,
							MaxVersion:           ver.version,
							CipherSuites:         []uint16{suite.id},
							Certificates:         []Certificate{cert},
							PreSharedKey:         []byte(psk),
							PreSharedKeyIdentity: pskIdentity,
						},
						flags:      flags,
						messageLen: maxPlaintext,
					})
				}
			}
		}
	}

	testCases = append(testCases, testCase{
		name: "NoSharedCipher",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{},
		},
		shouldFail:    true,
		expectedError: ":HANDSHAKE_FAILURE_ON_CLIENT_HELLO:",
	})

	testCases = append(testCases, testCase{
		name: "NoSharedCipher-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			CipherSuites: []uint16{},
		},
		shouldFail:    true,
		expectedError: ":HANDSHAKE_FAILURE_ON_CLIENT_HELLO:",
	})

	testCases = append(testCases, testCase{
		name: "UnsupportedCipherSuite",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA},
			Bugs: ProtocolBugs{
				IgnorePeerCipherPreferences: true,
			},
		},
		flags:         []string{"-cipher", "DEFAULT:!RC4"},
		shouldFail:    true,
		expectedError: ":WRONG_CIPHER_RETURNED:",
	})

	testCases = append(testCases, testCase{
		name: "ServerHelloBogusCipher",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				SendCipherSuite: bogusCipher,
			},
		},
		shouldFail:    true,
		expectedError: ":UNKNOWN_CIPHER_RETURNED:",
	})
	testCases = append(testCases, testCase{
		name: "ServerHelloBogusCipher-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SendCipherSuite: bogusCipher,
			},
		},
		shouldFail:    true,
		expectedError: ":UNKNOWN_CIPHER_RETURNED:",
	})

	testCases = append(testCases, testCase{
		name: "WeakDH",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				// This is a 1023-bit prime number, generated
				// with:
				// openssl gendh 1023 | openssl asn1parse -i
				DHGroupPrime: bigFromHex("518E9B7930CE61C6E445C8360584E5FC78D9137C0FFDC880B495D5338ADF7689951A6821C17A76B3ACB8E0156AEA607B7EC406EBEDBB84D8376EB8FE8F8BA1433488BEE0C3EDDFD3A32DBB9481980A7AF6C96BFCF490A094CFFB2B8192C1BB5510B77B658436E27C2D4D023FE3718222AB0CA1273995B51F6D625A4944D0DD4B"),
			},
		},
		shouldFail:    true,
		expectedError: ":BAD_DH_P_LENGTH:",
	})

	testCases = append(testCases, testCase{
		name: "SillyDH",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				// This is a 4097-bit prime number, generated
				// with:
				// openssl gendh 4097 | openssl asn1parse -i
				DHGroupPrime: bigFromHex("01D366FA64A47419B0CD4A45918E8D8C8430F674621956A9F52B0CA592BC104C6E38D60C58F2CA66792A2B7EBDC6F8FFE75AB7D6862C261F34E96A2AEEF53AB7C21365C2E8FB0582F71EB57B1C227C0E55AE859E9904A25EFECD7B435C4D4357BD840B03649D4A1F8037D89EA4E1967DBEEF1CC17A6111C48F12E9615FFF336D3F07064CB17C0B765A012C850B9E3AA7A6984B96D8C867DDC6D0F4AB52042572244796B7ECFF681CD3B3E2E29AAECA391A775BEE94E502FB15881B0F4AC60314EA947C0C82541C3D16FD8C0E09BB7F8F786582032859D9C13187CE6C0CB6F2D3EE6C3C9727C15F14B21D3CD2E02BDB9D119959B0E03DC9E5A91E2578762300B1517D2352FC1D0BB934A4C3E1B20CE9327DB102E89A6C64A8C3148EDFC5A94913933853442FA84451B31FD21E492F92DD5488E0D871AEBFE335A4B92431DEC69591548010E76A5B365D346786E9A2D3E589867D796AA5E25211201D757560D318A87DFB27F3E625BC373DB48BF94A63161C674C3D4265CB737418441B7650EABC209CF675A439BEB3E9D1AA1B79F67198A40CEFD1C89144F7D8BAF61D6AD36F466DA546B4174A0E0CAF5BD788C8243C7C2DDDCC3DB6FC89F12F17D19FBD9B0BC76FE92891CD6BA07BEA3B66EF12D0D85E788FD58675C1B0FBD16029DCC4D34E7A1A41471BDEDF78BF591A8B4E96D88BEC8EDC093E616292BFC096E69A916E8D624B"),
			},
		},
		shouldFail:    true,
		expectedError: ":DH_P_TOO_LONG:",
	})

	// This test ensures that Diffie-Hellman public values are padded with
	// zeros so that they're the same length as the prime. This is to avoid
	// hitting a bug in yaSSL.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "DHPublicValuePadded",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				RequireDHPublicValueLen: (1025 + 7) / 8,
			},
		},
		flags: []string{"-use-sparse-dh-prime"},
	})

	// The server must be tolerant to bogus ciphers.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "UnknownCipher",
		config: Config{
			CipherSuites: []uint16{bogusCipher, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
	})

	// versionSpecificCiphersTest specifies a test for the TLS 1.0 and TLS
	// 1.1 specific cipher suite settings. A server is setup with the given
	// cipher lists and then a connection is made for each member of
	// expectations. The cipher suite that the server selects must match
	// the specified one.
	var versionSpecificCiphersTest = []struct {
		ciphersDefault, ciphersTLS10, ciphersTLS11 string
		// expectations is a map from TLS version to cipher suite id.
		expectations map[uint16]uint16
	}{
		{
			// Test that the null case (where no version-specific ciphers are set)
			// works as expected.
			"RC4-SHA:AES128-SHA", // default ciphers
			"",                   // no ciphers specifically for TLS ≥ 1.0
			"",                   // no ciphers specifically for TLS ≥ 1.1
			map[uint16]uint16{
				VersionSSL30: TLS_RSA_WITH_RC4_128_SHA,
				VersionTLS10: TLS_RSA_WITH_RC4_128_SHA,
				VersionTLS11: TLS_RSA_WITH_RC4_128_SHA,
				VersionTLS12: TLS_RSA_WITH_RC4_128_SHA,
			},
		},
		{
			// With ciphers_tls10 set, TLS 1.0, 1.1 and 1.2 should get a different
			// cipher.
			"RC4-SHA:AES128-SHA", // default
			"AES128-SHA",         // these ciphers for TLS ≥ 1.0
			"",                   // no ciphers specifically for TLS ≥ 1.1
			map[uint16]uint16{
				VersionSSL30: TLS_RSA_WITH_RC4_128_SHA,
				VersionTLS10: TLS_RSA_WITH_AES_128_CBC_SHA,
				VersionTLS11: TLS_RSA_WITH_AES_128_CBC_SHA,
				VersionTLS12: TLS_RSA_WITH_AES_128_CBC_SHA,
			},
		},
		{
			// With ciphers_tls11 set, TLS 1.1 and 1.2 should get a different
			// cipher.
			"RC4-SHA:AES128-SHA", // default
			"",                   // no ciphers specifically for TLS ≥ 1.0
			"AES128-SHA",         // these ciphers for TLS ≥ 1.1
			map[uint16]uint16{
				VersionSSL30: TLS_RSA_WITH_RC4_128_SHA,
				VersionTLS10: TLS_RSA_WITH_RC4_128_SHA,
				VersionTLS11: TLS_RSA_WITH_AES_128_CBC_SHA,
				VersionTLS12: TLS_RSA_WITH_AES_128_CBC_SHA,
			},
		},
		{
			// With both ciphers_tls10 and ciphers_tls11 set, ciphers_tls11 should
			// mask ciphers_tls10 for TLS 1.1 and 1.2.
			"RC4-SHA:AES128-SHA", // default
			"AES128-SHA",         // these ciphers for TLS ≥ 1.0
			"AES256-SHA",         // these ciphers for TLS ≥ 1.1
			map[uint16]uint16{
				VersionSSL30: TLS_RSA_WITH_RC4_128_SHA,
				VersionTLS10: TLS_RSA_WITH_AES_128_CBC_SHA,
				VersionTLS11: TLS_RSA_WITH_AES_256_CBC_SHA,
				VersionTLS12: TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		},
	}

	for i, test := range versionSpecificCiphersTest {
		for version, expectedCipherSuite := range test.expectations {
			flags := []string{"-cipher", test.ciphersDefault}
			if len(test.ciphersTLS10) > 0 {
				flags = append(flags, "-cipher-tls10", test.ciphersTLS10)
			}
			if len(test.ciphersTLS11) > 0 {
				flags = append(flags, "-cipher-tls11", test.ciphersTLS11)
			}

			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     fmt.Sprintf("VersionSpecificCiphersTest-%d-%x", i, version),
				config: Config{
					MaxVersion:   version,
					MinVersion:   version,
					CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA},
				},
				flags:          flags,
				expectedCipher: expectedCipherSuite,
			})
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
					Certificates: []Certificate{ecdsaP256Certificate},
					Bugs: ProtocolBugs{
						BadECDSAR: badR,
						BadECDSAS: badS,
					},
				},
				shouldFail:    true,
				expectedError: ":BAD_SIGNATURE:",
			})
		}
	}
}

func addCBCPaddingTests() {
	testCases = append(testCases, testCase{
		name: "MaxCBCPadding",
		config: Config{
			MaxVersion:   VersionTLS12,
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
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			Bugs: ProtocolBugs{
				PaddingFirstByteBad: true,
			},
		},
		shouldFail:    true,
		expectedError: ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
	})
	// OpenSSL previously had an issue where the first byte of padding in
	// 255 bytes of padding wasn't checked.
	testCases = append(testCases, testCase{
		name: "BadCBCPadding255",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			Bugs: ProtocolBugs{
				MaxPadding:               true,
				PaddingFirstByteBadIf255: true,
			},
		},
		messageLen:    12, // 20 bytes of SHA-1 + 12 == 0 % block size
		shouldFail:    true,
		expectedError: ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
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
		messageLen:    -1, // read until EOF
		resumeSession: true,
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
		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     ver.name + "-Client-ClientAuth-RSA",
			config: Config{
				MinVersion: ver.version,
				MaxVersion: ver.version,
				ClientAuth: RequireAnyClientCert,
				ClientCAs:  certPool,
			},
			flags: []string{
				"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
				"-key-file", path.Join(*resourceDir, rsaKeyFile),
			},
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     ver.name + "-Server-ClientAuth-RSA",
			config: Config{
				MinVersion:   ver.version,
				MaxVersion:   ver.version,
				Certificates: []Certificate{rsaCertificate},
			},
			flags: []string{"-require-any-client-certificate"},
		})
		if ver.version != VersionSSL30 {
			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     ver.name + "-Server-ClientAuth-ECDSA",
				config: Config{
					MinVersion:   ver.version,
					MaxVersion:   ver.version,
					Certificates: []Certificate{ecdsaP256Certificate},
				},
				flags: []string{"-require-any-client-certificate"},
			})
			testCases = append(testCases, testCase{
				testType: clientTest,
				name:     ver.name + "-Client-ClientAuth-ECDSA",
				config: Config{
					MinVersion: ver.version,
					MaxVersion: ver.version,
					ClientAuth: RequireAnyClientCert,
					ClientCAs:  certPool,
				},
				flags: []string{
					"-cert-file", path.Join(*resourceDir, ecdsaP256CertificateFile),
					"-key-file", path.Join(*resourceDir, ecdsaP256KeyFile),
				},
			})
		}
	}

	testCases = append(testCases, testCase{
		name: "NoClientCertificate",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequireAnyClientCert,
		},
		shouldFail:         true,
		expectedLocalError: "client didn't provide a certificate",
	})

	testCases = append(testCases, testCase{
		name: "NoClientCertificate-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			ClientAuth: RequireAnyClientCert,
		},
		shouldFail:         true,
		expectedLocalError: "client didn't provide a certificate",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "RequireAnyClientCertificate",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		flags:         []string{"-require-any-client-certificate"},
		shouldFail:    true,
		expectedError: ":PEER_DID_NOT_RETURN_A_CERTIFICATE:",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "RequireAnyClientCertificate-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
		},
		flags:         []string{"-require-any-client-certificate"},
		shouldFail:    true,
		expectedError: ":PEER_DID_NOT_RETURN_A_CERTIFICATE:",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "RequireAnyClientCertificate-SSL3",
		config: Config{
			MaxVersion: VersionSSL30,
		},
		flags:         []string{"-require-any-client-certificate"},
		shouldFail:    true,
		expectedError: ":PEER_DID_NOT_RETURN_A_CERTIFICATE:",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SkipClientCertificate",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				SkipClientCertificate: true,
			},
		},
		// Setting SSL_VERIFY_PEER allows anonymous clients.
		flags:         []string{"-verify-peer"},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SkipClientCertificate-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SkipClientCertificate: true,
			},
		},
		// Setting SSL_VERIFY_PEER allows anonymous clients.
		flags:         []string{"-verify-peer"},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
	})

	// Client auth is only legal in certificate-based ciphers.
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "ClientAuth-PSK",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_PSK_WITH_AES_128_CBC_SHA},
			PreSharedKey: []byte("secret"),
			ClientAuth:   RequireAnyClientCert,
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
			"-psk", "secret",
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
	})
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "ClientAuth-ECDHE_PSK",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA},
			PreSharedKey: []byte("secret"),
			ClientAuth:   RequireAnyClientCert,
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
			"-psk", "secret",
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
	})

	// Regression test for a bug where the client CA list, if explicitly
	// set to NULL, was mis-encoded.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "Null-Client-CA-List",
		config: Config{
			MaxVersion:   VersionTLS12,
			Certificates: []Certificate{rsaCertificate},
		},
		flags: []string{
			"-require-any-client-certificate",
			"-use-null-client-ca-list",
		},
	})
}

func addExtendedMasterSecretTests() {
	const expectEMSFlag = "-expect-extended-master-secret"

	for _, with := range []bool{false, true} {
		prefix := "No"
		if with {
			prefix = ""
		}

		for _, isClient := range []bool{false, true} {
			suffix := "-Server"
			testType := serverTest
			if isClient {
				suffix = "-Client"
				testType = clientTest
			}

			for _, ver := range tlsVersions {
				// In TLS 1.3, the extension is irrelevant and
				// always reports as enabled.
				var flags []string
				if with || ver.version >= VersionTLS13 {
					flags = []string{expectEMSFlag}
				}

				test := testCase{
					testType: testType,
					name:     prefix + "ExtendedMasterSecret-" + ver.name + suffix,
					config: Config{
						MinVersion: ver.version,
						MaxVersion: ver.version,
						Bugs: ProtocolBugs{
							NoExtendedMasterSecret:      !with,
							RequireExtendedMasterSecret: with,
						},
					},
					flags:      flags,
					shouldFail: ver.version == VersionSSL30 && with,
				}
				if test.shouldFail {
					test.expectedLocalError = "extended master secret required but not supported by peer"
				}
				testCases = append(testCases, test)
			}
		}
	}

	for _, isClient := range []bool{false, true} {
		for _, supportedInFirstConnection := range []bool{false, true} {
			for _, supportedInResumeConnection := range []bool{false, true} {
				boolToWord := func(b bool) string {
					if b {
						return "Yes"
					}
					return "No"
				}
				suffix := boolToWord(supportedInFirstConnection) + "To" + boolToWord(supportedInResumeConnection) + "-"
				if isClient {
					suffix += "Client"
				} else {
					suffix += "Server"
				}

				supportedConfig := Config{
					MaxVersion: VersionTLS12,
					Bugs: ProtocolBugs{
						RequireExtendedMasterSecret: true,
					},
				}

				noSupportConfig := Config{
					MaxVersion: VersionTLS12,
					Bugs: ProtocolBugs{
						NoExtendedMasterSecret: true,
					},
				}

				test := testCase{
					name:          "ExtendedMasterSecret-" + suffix,
					resumeSession: true,
				}

				if !isClient {
					test.testType = serverTest
				}

				if supportedInFirstConnection {
					test.config = supportedConfig
				} else {
					test.config = noSupportConfig
				}

				if supportedInResumeConnection {
					test.resumeConfig = &supportedConfig
				} else {
					test.resumeConfig = &noSupportConfig
				}

				switch suffix {
				case "YesToYes-Client", "YesToYes-Server":
					// When a session is resumed, it should
					// still be aware that its master
					// secret was generated via EMS and
					// thus it's safe to use tls-unique.
					test.flags = []string{expectEMSFlag}
				case "NoToYes-Server":
					// If an original connection did not
					// contain EMS, but a resumption
					// handshake does, then a server should
					// not resume the session.
					test.expectResumeRejected = true
				case "YesToNo-Server":
					// Resuming an EMS session without the
					// EMS extension should cause the
					// server to abort the connection.
					test.shouldFail = true
					test.expectedError = ":RESUMED_EMS_SESSION_WITHOUT_EMS_EXTENSION:"
				case "NoToYes-Client":
					// A client should abort a connection
					// where the server resumed a non-EMS
					// session but echoed the EMS
					// extension.
					test.shouldFail = true
					test.expectedError = ":RESUMED_NON_EMS_SESSION_WITH_EMS_EXTENSION:"
				case "YesToNo-Client":
					// A client should abort a connection
					// where the server didn't echo EMS
					// when the session used it.
					test.shouldFail = true
					test.expectedError = ":RESUMED_EMS_SESSION_WITHOUT_EMS_EXTENSION:"
				}

				testCases = append(testCases, test)
			}
		}
	}
}

type stateMachineTestConfig struct {
	protocol                            protocol
	async                               bool
	splitHandshake, packHandshakeFlight bool
}

// Adds tests that try to cover the range of the handshake state machine, under
// various conditions. Some of these are redundant with other tests, but they
// only cover the synchronous case.
func addAllStateMachineCoverageTests() {
	for _, async := range []bool{false, true} {
		for _, protocol := range []protocol{tls, dtls} {
			addStateMachineCoverageTests(stateMachineTestConfig{
				protocol: protocol,
				async:    async,
			})
			addStateMachineCoverageTests(stateMachineTestConfig{
				protocol:       protocol,
				async:          async,
				splitHandshake: true,
			})
			if protocol == tls {
				addStateMachineCoverageTests(stateMachineTestConfig{
					protocol:            protocol,
					async:               async,
					packHandshakeFlight: true,
				})
			}
		}
	}
}

func addStateMachineCoverageTests(config stateMachineTestConfig) {
	var tests []testCase

	// Basic handshake, with resumption. Client and server,
	// session ID and session ticket.
	tests = append(tests, testCase{
		name: "Basic-Client",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		resumeSession: true,
		// Ensure session tickets are used, not session IDs.
		noSessionCache: true,
	})
	tests = append(tests, testCase{
		name: "Basic-Client-RenewTicket",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				RenewTicketOnResume: true,
			},
		},
		flags:         []string{"-expect-ticket-renewal"},
		resumeSession: true,
	})
	tests = append(tests, testCase{
		name: "Basic-Client-NoTicket",
		config: Config{
			MaxVersion:             VersionTLS12,
			SessionTicketsDisabled: true,
		},
		resumeSession: true,
	})
	tests = append(tests, testCase{
		name: "Basic-Client-Implicit",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		flags:         []string{"-implicit-handshake"},
		resumeSession: true,
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "Basic-Server",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				RequireSessionTickets: true,
			},
		},
		resumeSession: true,
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "Basic-Server-NoTickets",
		config: Config{
			MaxVersion:             VersionTLS12,
			SessionTicketsDisabled: true,
		},
		resumeSession: true,
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "Basic-Server-Implicit",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		flags:         []string{"-implicit-handshake"},
		resumeSession: true,
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "Basic-Server-EarlyCallback",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		flags:         []string{"-use-early-callback"},
		resumeSession: true,
	})

	// TLS 1.3 basic handshake shapes.
	tests = append(tests, testCase{
		name: "TLS13-1RTT-Client",
		config: Config{
			MaxVersion: VersionTLS13,
		},
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "TLS13-1RTT-Server",
		config: Config{
			MaxVersion: VersionTLS13,
		},
	})

	// TLS client auth.
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "ClientAuth-NoCertificate-Client",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequestClientCert,
		},
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "ClientAuth-NoCertificate-Server",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		// Setting SSL_VERIFY_PEER allows anonymous clients.
		flags: []string{"-verify-peer"},
	})
	if config.protocol == tls {
		tests = append(tests, testCase{
			testType: clientTest,
			name:     "ClientAuth-NoCertificate-Client-SSL3",
			config: Config{
				MaxVersion: VersionSSL30,
				ClientAuth: RequestClientCert,
			},
		})
		tests = append(tests, testCase{
			testType: serverTest,
			name:     "ClientAuth-NoCertificate-Server-SSL3",
			config: Config{
				MaxVersion: VersionSSL30,
			},
			// Setting SSL_VERIFY_PEER allows anonymous clients.
			flags: []string{"-verify-peer"},
		})
		tests = append(tests, testCase{
			testType: clientTest,
			name:     "ClientAuth-NoCertificate-Client-TLS13",
			config: Config{
				MaxVersion: VersionTLS13,
				ClientAuth: RequestClientCert,
			},
		})
		tests = append(tests, testCase{
			testType: serverTest,
			name:     "ClientAuth-NoCertificate-Server-TLS13",
			config: Config{
				MaxVersion: VersionTLS13,
			},
			// Setting SSL_VERIFY_PEER allows anonymous clients.
			flags: []string{"-verify-peer"},
		})
	}
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "ClientAuth-RSA-Client",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequireAnyClientCert,
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
		},
	})
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "ClientAuth-RSA-Client-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			ClientAuth: RequireAnyClientCert,
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
		},
	})
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "ClientAuth-ECDSA-Client",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequireAnyClientCert,
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, ecdsaP256CertificateFile),
			"-key-file", path.Join(*resourceDir, ecdsaP256KeyFile),
		},
	})
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "ClientAuth-ECDSA-Client-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			ClientAuth: RequireAnyClientCert,
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, ecdsaP256CertificateFile),
			"-key-file", path.Join(*resourceDir, ecdsaP256KeyFile),
		},
	})
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "ClientAuth-NoCertificate-OldCallback",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequestClientCert,
		},
		flags: []string{"-use-old-client-cert-callback"},
	})
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "ClientAuth-NoCertificate-OldCallback-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			ClientAuth: RequestClientCert,
		},
		flags: []string{"-use-old-client-cert-callback"},
	})
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "ClientAuth-OldCallback",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequireAnyClientCert,
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
			"-use-old-client-cert-callback",
		},
	})
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "ClientAuth-OldCallback-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			ClientAuth: RequireAnyClientCert,
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
			"-use-old-client-cert-callback",
		},
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "ClientAuth-Server",
		config: Config{
			MaxVersion:   VersionTLS12,
			Certificates: []Certificate{rsaCertificate},
		},
		flags: []string{"-require-any-client-certificate"},
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "ClientAuth-Server-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			Certificates: []Certificate{rsaCertificate},
		},
		flags: []string{"-require-any-client-certificate"},
	})

	// Test each key exchange on the server side for async keys.
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "Basic-Server-RSA",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
		},
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "Basic-Server-ECDHE-RSA",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
		},
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "Basic-Server-ECDHE-ECDSA",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, ecdsaP256CertificateFile),
			"-key-file", path.Join(*resourceDir, ecdsaP256KeyFile),
		},
	})

	// No session ticket support; server doesn't send NewSessionTicket.
	tests = append(tests, testCase{
		name: "SessionTicketsDisabled-Client",
		config: Config{
			MaxVersion:             VersionTLS12,
			SessionTicketsDisabled: true,
		},
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "SessionTicketsDisabled-Server",
		config: Config{
			MaxVersion:             VersionTLS12,
			SessionTicketsDisabled: true,
		},
	})

	// Skip ServerKeyExchange in PSK key exchange if there's no
	// identity hint.
	tests = append(tests, testCase{
		name: "EmptyPSKHint-Client",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_PSK_WITH_AES_128_CBC_SHA},
			PreSharedKey: []byte("secret"),
		},
		flags: []string{"-psk", "secret"},
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "EmptyPSKHint-Server",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_PSK_WITH_AES_128_CBC_SHA},
			PreSharedKey: []byte("secret"),
		},
		flags: []string{"-psk", "secret"},
	})

	// OCSP stapling tests.
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "OCSPStapling-Client",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		flags: []string{
			"-enable-ocsp-stapling",
			"-expect-ocsp-response",
			base64.StdEncoding.EncodeToString(testOCSPResponse),
			"-verify-peer",
		},
		resumeSession: true,
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "OCSPStapling-Server",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		expectedOCSPResponse: testOCSPResponse,
		flags: []string{
			"-ocsp-response",
			base64.StdEncoding.EncodeToString(testOCSPResponse),
		},
		resumeSession: true,
	})
	tests = append(tests, testCase{
		testType: clientTest,
		name:     "OCSPStapling-Client-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
		},
		flags: []string{
			"-enable-ocsp-stapling",
			"-expect-ocsp-response",
			base64.StdEncoding.EncodeToString(testOCSPResponse),
			"-verify-peer",
		},
		// TODO(davidben): Enable this when resumption is implemented
		// in TLS 1.3.
		resumeSession: false,
	})
	tests = append(tests, testCase{
		testType: serverTest,
		name:     "OCSPStapling-Server-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
		},
		expectedOCSPResponse: testOCSPResponse,
		flags: []string{
			"-ocsp-response",
			base64.StdEncoding.EncodeToString(testOCSPResponse),
		},
		// TODO(davidben): Enable this when resumption is implemented
		// in TLS 1.3.
		resumeSession: false,
	})

	// Certificate verification tests.
	for _, vers := range tlsVersions {
		if config.protocol == dtls && !vers.hasDTLS {
			continue
		}
		tests = append(tests, testCase{
			testType: clientTest,
			name:     "CertificateVerificationSucceed-" + vers.name,
			config: Config{
				MaxVersion: vers.version,
			},
			flags: []string{
				"-verify-peer",
			},
		})
		tests = append(tests, testCase{
			testType: clientTest,
			name:     "CertificateVerificationFail-" + vers.name,
			config: Config{
				MaxVersion: vers.version,
			},
			flags: []string{
				"-verify-fail",
				"-verify-peer",
			},
			shouldFail:    true,
			expectedError: ":CERTIFICATE_VERIFY_FAILED:",
		})
		tests = append(tests, testCase{
			testType: clientTest,
			name:     "CertificateVerificationSoftFail-" + vers.name,
			config: Config{
				MaxVersion: vers.version,
			},
			flags: []string{
				"-verify-fail",
				"-expect-verify-result",
			},
		})
	}

	if config.protocol == tls {
		tests = append(tests, testCase{
			name: "Renegotiate-Client",
			config: Config{
				MaxVersion: VersionTLS12,
			},
			renegotiate: 1,
			flags: []string{
				"-renegotiate-freely",
				"-expect-total-renegotiations", "1",
			},
		})

		// NPN on client and server; results in post-handshake message.
		tests = append(tests, testCase{
			name: "NPN-Client",
			config: Config{
				MaxVersion: VersionTLS12,
				NextProtos: []string{"foo"},
			},
			flags:                 []string{"-select-next-proto", "foo"},
			resumeSession:         true,
			expectedNextProto:     "foo",
			expectedNextProtoType: npn,
		})
		tests = append(tests, testCase{
			testType: serverTest,
			name:     "NPN-Server",
			config: Config{
				MaxVersion: VersionTLS12,
				NextProtos: []string{"bar"},
			},
			flags: []string{
				"-advertise-npn", "\x03foo\x03bar\x03baz",
				"-expect-next-proto", "bar",
			},
			resumeSession:         true,
			expectedNextProto:     "bar",
			expectedNextProtoType: npn,
		})

		// TODO(davidben): Add tests for when False Start doesn't trigger.

		// Client does False Start and negotiates NPN.
		tests = append(tests, testCase{
			name: "FalseStart",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					ExpectFalseStart: true,
				},
			},
			flags: []string{
				"-false-start",
				"-select-next-proto", "foo",
			},
			shimWritesFirst: true,
			resumeSession:   true,
		})

		// Client does False Start and negotiates ALPN.
		tests = append(tests, testCase{
			name: "FalseStart-ALPN",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					ExpectFalseStart: true,
				},
			},
			flags: []string{
				"-false-start",
				"-advertise-alpn", "\x03foo",
			},
			shimWritesFirst: true,
			resumeSession:   true,
		})

		// Client does False Start but doesn't explicitly call
		// SSL_connect.
		tests = append(tests, testCase{
			name: "FalseStart-Implicit",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
			},
			flags: []string{
				"-implicit-handshake",
				"-false-start",
				"-advertise-alpn", "\x03foo",
			},
		})

		// False Start without session tickets.
		tests = append(tests, testCase{
			name: "FalseStart-SessionTicketsDisabled",
			config: Config{
				MaxVersion:             VersionTLS12,
				CipherSuites:           []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:             []string{"foo"},
				SessionTicketsDisabled: true,
				Bugs: ProtocolBugs{
					ExpectFalseStart: true,
				},
			},
			flags: []string{
				"-false-start",
				"-select-next-proto", "foo",
			},
			shimWritesFirst: true,
		})

		tests = append(tests, testCase{
			name: "FalseStart-CECPQ1",
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					ExpectFalseStart: true,
				},
			},
			flags: []string{
				"-false-start",
				"-cipher", "DEFAULT:kCECPQ1",
				"-select-next-proto", "foo",
			},
			shimWritesFirst: true,
			resumeSession:   true,
		})

		// Server parses a V2ClientHello.
		tests = append(tests, testCase{
			testType: serverTest,
			name:     "SendV2ClientHello",
			config: Config{
				// Choose a cipher suite that does not involve
				// elliptic curves, so no extensions are
				// involved.
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA},
				Bugs: ProtocolBugs{
					SendV2ClientHello: true,
				},
			},
		})

		// Client sends a Channel ID.
		tests = append(tests, testCase{
			name: "ChannelID-Client",
			config: Config{
				MaxVersion:       VersionTLS12,
				RequestChannelID: true,
			},
			flags:           []string{"-send-channel-id", path.Join(*resourceDir, channelIDKeyFile)},
			resumeSession:   true,
			expectChannelID: true,
		})

		// Server accepts a Channel ID.
		tests = append(tests, testCase{
			testType: serverTest,
			name:     "ChannelID-Server",
			config: Config{
				MaxVersion: VersionTLS12,
				ChannelID:  channelIDKey,
			},
			flags: []string{
				"-expect-channel-id",
				base64.StdEncoding.EncodeToString(channelIDBytes),
			},
			resumeSession:   true,
			expectChannelID: true,
		})

		// Channel ID and NPN at the same time, to ensure their relative
		// ordering is correct.
		tests = append(tests, testCase{
			name: "ChannelID-NPN-Client",
			config: Config{
				MaxVersion:       VersionTLS12,
				RequestChannelID: true,
				NextProtos:       []string{"foo"},
			},
			flags: []string{
				"-send-channel-id", path.Join(*resourceDir, channelIDKeyFile),
				"-select-next-proto", "foo",
			},
			resumeSession:         true,
			expectChannelID:       true,
			expectedNextProto:     "foo",
			expectedNextProtoType: npn,
		})
		tests = append(tests, testCase{
			testType: serverTest,
			name:     "ChannelID-NPN-Server",
			config: Config{
				MaxVersion: VersionTLS12,
				ChannelID:  channelIDKey,
				NextProtos: []string{"bar"},
			},
			flags: []string{
				"-expect-channel-id",
				base64.StdEncoding.EncodeToString(channelIDBytes),
				"-advertise-npn", "\x03foo\x03bar\x03baz",
				"-expect-next-proto", "bar",
			},
			resumeSession:         true,
			expectChannelID:       true,
			expectedNextProto:     "bar",
			expectedNextProtoType: npn,
		})

		// Bidirectional shutdown with the runner initiating.
		tests = append(tests, testCase{
			name: "Shutdown-Runner",
			config: Config{
				Bugs: ProtocolBugs{
					ExpectCloseNotify: true,
				},
			},
			flags: []string{"-check-close-notify"},
		})

		// Bidirectional shutdown with the shim initiating. The runner,
		// in the meantime, sends garbage before the close_notify which
		// the shim must ignore.
		tests = append(tests, testCase{
			name: "Shutdown-Shim",
			config: Config{
				Bugs: ProtocolBugs{
					ExpectCloseNotify: true,
				},
			},
			shimShutsDown:     true,
			sendEmptyRecords:  1,
			sendWarningAlerts: 1,
			flags:             []string{"-check-close-notify"},
		})
	} else {
		// TODO(davidben): DTLS 1.3 will want a similar thing for
		// HelloRetryRequest.
		tests = append(tests, testCase{
			name: "SkipHelloVerifyRequest",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SkipHelloVerifyRequest: true,
				},
			},
		})
	}

	for _, test := range tests {
		test.protocol = config.protocol
		if config.protocol == dtls {
			test.name += "-DTLS"
		}
		if config.async {
			test.name += "-Async"
			test.flags = append(test.flags, "-async")
		} else {
			test.name += "-Sync"
		}
		if config.splitHandshake {
			test.name += "-SplitHandshakeRecords"
			test.config.Bugs.MaxHandshakeRecordLength = 1
			if config.protocol == dtls {
				test.config.Bugs.MaxPacketLength = 256
				test.flags = append(test.flags, "-mtu", "256")
			}
		}
		if config.packHandshakeFlight {
			test.name += "-PackHandshakeFlight"
			test.config.Bugs.PackHandshakeFlight = true
		}
		testCases = append(testCases, test)
	}
}

func addDDoSCallbackTests() {
	// DDoS callback.
	// TODO(davidben): Implement DDoS resumption tests for TLS 1.3.
	for _, resume := range []bool{false, true} {
		suffix := "Resume"
		if resume {
			suffix = "No" + suffix
		}

		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "Server-DDoS-OK-" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
			},
			flags:         []string{"-install-ddos-callback"},
			resumeSession: resume,
		})
		if !resume {
			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     "Server-DDoS-OK-" + suffix + "-TLS13",
				config: Config{
					MaxVersion: VersionTLS13,
				},
				flags:         []string{"-install-ddos-callback"},
				resumeSession: resume,
			})
		}

		failFlag := "-fail-ddos-callback"
		if resume {
			failFlag = "-fail-second-ddos-callback"
		}
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "Server-DDoS-Reject-" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
			},
			flags:         []string{"-install-ddos-callback", failFlag},
			resumeSession: resume,
			shouldFail:    true,
			expectedError: ":CONNECTION_REJECTED:",
		})
		if !resume {
			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     "Server-DDoS-Reject-" + suffix + "-TLS13",
				config: Config{
					MaxVersion: VersionTLS13,
				},
				flags:         []string{"-install-ddos-callback", failFlag},
				resumeSession: resume,
				shouldFail:    true,
				expectedError: ":CONNECTION_REJECTED:",
			})
		}
	}
}

func addVersionNegotiationTests() {
	for i, shimVers := range tlsVersions {
		// Assemble flags to disable all newer versions on the shim.
		var flags []string
		for _, vers := range tlsVersions[i+1:] {
			flags = append(flags, vers.flag)
		}

		for _, runnerVers := range tlsVersions {
			protocols := []protocol{tls}
			if runnerVers.hasDTLS && shimVers.hasDTLS {
				protocols = append(protocols, dtls)
			}
			for _, protocol := range protocols {
				expectedVersion := shimVers.version
				if runnerVers.version < shimVers.version {
					expectedVersion = runnerVers.version
				}

				suffix := shimVers.name + "-" + runnerVers.name
				if protocol == dtls {
					suffix += "-DTLS"
				}

				shimVersFlag := strconv.Itoa(int(versionToWire(shimVers.version, protocol == dtls)))

				clientVers := shimVers.version
				if clientVers > VersionTLS10 {
					clientVers = VersionTLS10
				}
				serverVers := expectedVersion
				if expectedVersion >= VersionTLS13 {
					serverVers = VersionTLS10
				}
				testCases = append(testCases, testCase{
					protocol: protocol,
					testType: clientTest,
					name:     "VersionNegotiation-Client-" + suffix,
					config: Config{
						MaxVersion: runnerVers.version,
						Bugs: ProtocolBugs{
							ExpectInitialRecordVersion: clientVers,
						},
					},
					flags:           flags,
					expectedVersion: expectedVersion,
				})
				testCases = append(testCases, testCase{
					protocol: protocol,
					testType: clientTest,
					name:     "VersionNegotiation-Client2-" + suffix,
					config: Config{
						MaxVersion: runnerVers.version,
						Bugs: ProtocolBugs{
							ExpectInitialRecordVersion: clientVers,
						},
					},
					flags:           []string{"-max-version", shimVersFlag},
					expectedVersion: expectedVersion,
				})

				testCases = append(testCases, testCase{
					protocol: protocol,
					testType: serverTest,
					name:     "VersionNegotiation-Server-" + suffix,
					config: Config{
						MaxVersion: runnerVers.version,
						Bugs: ProtocolBugs{
							ExpectInitialRecordVersion: serverVers,
						},
					},
					flags:           flags,
					expectedVersion: expectedVersion,
				})
				testCases = append(testCases, testCase{
					protocol: protocol,
					testType: serverTest,
					name:     "VersionNegotiation-Server2-" + suffix,
					config: Config{
						MaxVersion: runnerVers.version,
						Bugs: ProtocolBugs{
							ExpectInitialRecordVersion: serverVers,
						},
					},
					flags:           []string{"-max-version", shimVersFlag},
					expectedVersion: expectedVersion,
				})
			}
		}
	}

	// Test for version tolerance.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "MinorVersionTolerance",
		config: Config{
			Bugs: ProtocolBugs{
				SendClientVersion: 0x03ff,
			},
		},
		expectedVersion: VersionTLS13,
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "MajorVersionTolerance",
		config: Config{
			Bugs: ProtocolBugs{
				SendClientVersion: 0x0400,
			},
		},
		expectedVersion: VersionTLS13,
	})
	testCases = append(testCases, testCase{
		protocol: dtls,
		testType: serverTest,
		name:     "MinorVersionTolerance-DTLS",
		config: Config{
			Bugs: ProtocolBugs{
				SendClientVersion: 0x03ff,
			},
		},
		expectedVersion: VersionTLS12,
	})
	testCases = append(testCases, testCase{
		protocol: dtls,
		testType: serverTest,
		name:     "MajorVersionTolerance-DTLS",
		config: Config{
			Bugs: ProtocolBugs{
				SendClientVersion: 0x0400,
			},
		},
		expectedVersion: VersionTLS12,
	})

	// Test that versions below 3.0 are rejected.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "VersionTooLow",
		config: Config{
			Bugs: ProtocolBugs{
				SendClientVersion: 0x0200,
			},
		},
		shouldFail:    true,
		expectedError: ":UNSUPPORTED_PROTOCOL:",
	})
	testCases = append(testCases, testCase{
		protocol: dtls,
		testType: serverTest,
		name:     "VersionTooLow-DTLS",
		config: Config{
			Bugs: ProtocolBugs{
				// 0x0201 is the lowest version expressable in
				// DTLS.
				SendClientVersion: 0x0201,
			},
		},
		shouldFail:    true,
		expectedError: ":UNSUPPORTED_PROTOCOL:",
	})

	// Test TLS 1.3's downgrade signal.
	testCases = append(testCases, testCase{
		name: "Downgrade-TLS12-Client",
		config: Config{
			Bugs: ProtocolBugs{
				NegotiateVersion: VersionTLS12,
			},
		},
		shouldFail:    true,
		expectedError: ":DOWNGRADE_DETECTED:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "Downgrade-TLS12-Server",
		config: Config{
			Bugs: ProtocolBugs{
				SendClientVersion: VersionTLS12,
			},
		},
		shouldFail:         true,
		expectedLocalError: "tls: downgrade from TLS 1.3 detected",
	})
}

func addMinimumVersionTests() {
	for i, shimVers := range tlsVersions {
		// Assemble flags to disable all older versions on the shim.
		var flags []string
		for _, vers := range tlsVersions[:i] {
			flags = append(flags, vers.flag)
		}

		for _, runnerVers := range tlsVersions {
			protocols := []protocol{tls}
			if runnerVers.hasDTLS && shimVers.hasDTLS {
				protocols = append(protocols, dtls)
			}
			for _, protocol := range protocols {
				suffix := shimVers.name + "-" + runnerVers.name
				if protocol == dtls {
					suffix += "-DTLS"
				}
				shimVersFlag := strconv.Itoa(int(versionToWire(shimVers.version, protocol == dtls)))

				var expectedVersion uint16
				var shouldFail bool
				var expectedClientError, expectedServerError string
				var expectedClientLocalError, expectedServerLocalError string
				if runnerVers.version >= shimVers.version {
					expectedVersion = runnerVers.version
				} else {
					shouldFail = true
					expectedServerError = ":UNSUPPORTED_PROTOCOL:"
					expectedServerLocalError = "remote error: protocol version not supported"
					if shimVers.version >= VersionTLS13 && runnerVers.version <= VersionTLS11 {
						// If the client's minimum version is TLS 1.3 and the runner's
						// maximum is below TLS 1.2, the runner will fail to select a
						// cipher before the shim rejects the selected version.
						expectedClientError = ":SSLV3_ALERT_HANDSHAKE_FAILURE:"
						expectedClientLocalError = "tls: no cipher suite supported by both client and server"
					} else {
						expectedClientError = expectedServerError
						expectedClientLocalError = expectedServerLocalError
					}
				}

				testCases = append(testCases, testCase{
					protocol: protocol,
					testType: clientTest,
					name:     "MinimumVersion-Client-" + suffix,
					config: Config{
						MaxVersion: runnerVers.version,
					},
					flags:              flags,
					expectedVersion:    expectedVersion,
					shouldFail:         shouldFail,
					expectedError:      expectedClientError,
					expectedLocalError: expectedClientLocalError,
				})
				testCases = append(testCases, testCase{
					protocol: protocol,
					testType: clientTest,
					name:     "MinimumVersion-Client2-" + suffix,
					config: Config{
						MaxVersion: runnerVers.version,
					},
					flags:              []string{"-min-version", shimVersFlag},
					expectedVersion:    expectedVersion,
					shouldFail:         shouldFail,
					expectedError:      expectedClientError,
					expectedLocalError: expectedClientLocalError,
				})

				testCases = append(testCases, testCase{
					protocol: protocol,
					testType: serverTest,
					name:     "MinimumVersion-Server-" + suffix,
					config: Config{
						MaxVersion: runnerVers.version,
					},
					flags:              flags,
					expectedVersion:    expectedVersion,
					shouldFail:         shouldFail,
					expectedError:      expectedServerError,
					expectedLocalError: expectedServerLocalError,
				})
				testCases = append(testCases, testCase{
					protocol: protocol,
					testType: serverTest,
					name:     "MinimumVersion-Server2-" + suffix,
					config: Config{
						MaxVersion: runnerVers.version,
					},
					flags:              []string{"-min-version", shimVersFlag},
					expectedVersion:    expectedVersion,
					shouldFail:         shouldFail,
					expectedError:      expectedServerError,
					expectedLocalError: expectedServerLocalError,
				})
			}
		}
	}
}

func addExtensionTests() {
	// TODO(davidben): Extensions, where applicable, all move their server
	// halves to EncryptedExtensions in TLS 1.3. Duplicate each of these
	// tests for both. Also test interaction with 0-RTT when implemented.

	// Repeat extensions tests all versions except SSL 3.0.
	for _, ver := range tlsVersions {
		if ver.version == VersionSSL30 {
			continue
		}

		// TODO(davidben): Implement resumption in TLS 1.3.
		resumeSession := ver.version < VersionTLS13

		// Test that duplicate extensions are rejected.
		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     "DuplicateExtensionClient-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				Bugs: ProtocolBugs{
					DuplicateExtension: true,
				},
			},
			shouldFail:         true,
			expectedLocalError: "remote error: error decoding message",
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "DuplicateExtensionServer-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				Bugs: ProtocolBugs{
					DuplicateExtension: true,
				},
			},
			shouldFail:         true,
			expectedLocalError: "remote error: error decoding message",
		})

		// Test SNI.
		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     "ServerNameExtensionClient-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				Bugs: ProtocolBugs{
					ExpectServerName: "example.com",
				},
			},
			flags: []string{"-host-name", "example.com"},
		})
		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     "ServerNameExtensionClientMismatch-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				Bugs: ProtocolBugs{
					ExpectServerName: "mismatch.com",
				},
			},
			flags:              []string{"-host-name", "example.com"},
			shouldFail:         true,
			expectedLocalError: "tls: unexpected server name",
		})
		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     "ServerNameExtensionClientMissing-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				Bugs: ProtocolBugs{
					ExpectServerName: "missing.com",
				},
			},
			shouldFail:         true,
			expectedLocalError: "tls: unexpected server name",
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "ServerNameExtensionServer-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				ServerName: "example.com",
			},
			flags:         []string{"-expect-server-name", "example.com"},
			resumeSession: resumeSession,
		})

		// Test ALPN.
		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     "ALPNClient-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				NextProtos: []string{"foo"},
			},
			flags: []string{
				"-advertise-alpn", "\x03foo\x03bar\x03baz",
				"-expect-alpn", "foo",
			},
			expectedNextProto:     "foo",
			expectedNextProtoType: alpn,
			resumeSession:         resumeSession,
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "ALPNServer-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				NextProtos: []string{"foo", "bar", "baz"},
			},
			flags: []string{
				"-expect-advertised-alpn", "\x03foo\x03bar\x03baz",
				"-select-alpn", "foo",
			},
			expectedNextProto:     "foo",
			expectedNextProtoType: alpn,
			resumeSession:         resumeSession,
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "ALPNServer-Decline-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				NextProtos: []string{"foo", "bar", "baz"},
			},
			flags:             []string{"-decline-alpn"},
			expectNoNextProto: true,
			resumeSession:     resumeSession,
		})

		var emptyString string
		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     "ALPNClient-EmptyProtocolName-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				NextProtos: []string{""},
				Bugs: ProtocolBugs{
					// A server returning an empty ALPN protocol
					// should be rejected.
					ALPNProtocol: &emptyString,
				},
			},
			flags: []string{
				"-advertise-alpn", "\x03foo",
			},
			shouldFail:    true,
			expectedError: ":PARSE_TLSEXT:",
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "ALPNServer-EmptyProtocolName-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				// A ClientHello containing an empty ALPN protocol
				// should be rejected.
				NextProtos: []string{"foo", "", "baz"},
			},
			flags: []string{
				"-select-alpn", "foo",
			},
			shouldFail:    true,
			expectedError: ":PARSE_TLSEXT:",
		})

		// Test NPN and the interaction with ALPN.
		if ver.version < VersionTLS13 {
			// Test that the server prefers ALPN over NPN.
			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     "ALPNServer-Preferred-" + ver.name,
				config: Config{
					MaxVersion: ver.version,
					NextProtos: []string{"foo", "bar", "baz"},
				},
				flags: []string{
					"-expect-advertised-alpn", "\x03foo\x03bar\x03baz",
					"-select-alpn", "foo",
					"-advertise-npn", "\x03foo\x03bar\x03baz",
				},
				expectedNextProto:     "foo",
				expectedNextProtoType: alpn,
				resumeSession:         resumeSession,
			})
			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     "ALPNServer-Preferred-Swapped-" + ver.name,
				config: Config{
					MaxVersion: ver.version,
					NextProtos: []string{"foo", "bar", "baz"},
					Bugs: ProtocolBugs{
						SwapNPNAndALPN: true,
					},
				},
				flags: []string{
					"-expect-advertised-alpn", "\x03foo\x03bar\x03baz",
					"-select-alpn", "foo",
					"-advertise-npn", "\x03foo\x03bar\x03baz",
				},
				expectedNextProto:     "foo",
				expectedNextProtoType: alpn,
				resumeSession:         resumeSession,
			})

			// Test that negotiating both NPN and ALPN is forbidden.
			testCases = append(testCases, testCase{
				name: "NegotiateALPNAndNPN-" + ver.name,
				config: Config{
					MaxVersion: ver.version,
					NextProtos: []string{"foo", "bar", "baz"},
					Bugs: ProtocolBugs{
						NegotiateALPNAndNPN: true,
					},
				},
				flags: []string{
					"-advertise-alpn", "\x03foo",
					"-select-next-proto", "foo",
				},
				shouldFail:    true,
				expectedError: ":NEGOTIATED_BOTH_NPN_AND_ALPN:",
			})
			testCases = append(testCases, testCase{
				name: "NegotiateALPNAndNPN-Swapped-" + ver.name,
				config: Config{
					MaxVersion: ver.version,
					NextProtos: []string{"foo", "bar", "baz"},
					Bugs: ProtocolBugs{
						NegotiateALPNAndNPN: true,
						SwapNPNAndALPN:      true,
					},
				},
				flags: []string{
					"-advertise-alpn", "\x03foo",
					"-select-next-proto", "foo",
				},
				shouldFail:    true,
				expectedError: ":NEGOTIATED_BOTH_NPN_AND_ALPN:",
			})

			// Test that NPN can be disabled with SSL_OP_DISABLE_NPN.
			testCases = append(testCases, testCase{
				name: "DisableNPN-" + ver.name,
				config: Config{
					MaxVersion: ver.version,
					NextProtos: []string{"foo"},
				},
				flags: []string{
					"-select-next-proto", "foo",
					"-disable-npn",
				},
				expectNoNextProto: true,
			})
		}

		// Test ticket behavior.
		//
		// TODO(davidben): Add TLS 1.3 versions of these.
		if ver.version < VersionTLS13 {
			// Resume with a corrupt ticket.
			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     "CorruptTicket-" + ver.name,
				config: Config{
					MaxVersion: ver.version,
					Bugs: ProtocolBugs{
						CorruptTicket: true,
					},
				},
				resumeSession:        true,
				expectResumeRejected: true,
			})
			// Test the ticket callback, with and without renewal.
			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     "TicketCallback-" + ver.name,
				config: Config{
					MaxVersion: ver.version,
				},
				resumeSession: true,
				flags:         []string{"-use-ticket-callback"},
			})
			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     "TicketCallback-Renew-" + ver.name,
				config: Config{
					MaxVersion: ver.version,
					Bugs: ProtocolBugs{
						ExpectNewTicket: true,
					},
				},
				flags:         []string{"-use-ticket-callback", "-renew-ticket"},
				resumeSession: true,
			})

			// Resume with an oversized session id.
			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     "OversizedSessionId-" + ver.name,
				config: Config{
					MaxVersion: ver.version,
					Bugs: ProtocolBugs{
						OversizedSessionId: true,
					},
				},
				resumeSession: true,
				shouldFail:    true,
				expectedError: ":DECODE_ERROR:",
			})
		}

		// Basic DTLS-SRTP tests. Include fake profiles to ensure they
		// are ignored.
		if ver.hasDTLS {
			testCases = append(testCases, testCase{
				protocol: dtls,
				name:     "SRTP-Client-" + ver.name,
				config: Config{
					MaxVersion:             ver.version,
					SRTPProtectionProfiles: []uint16{40, SRTP_AES128_CM_HMAC_SHA1_80, 42},
				},
				flags: []string{
					"-srtp-profiles",
					"SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32",
				},
				expectedSRTPProtectionProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			})
			testCases = append(testCases, testCase{
				protocol: dtls,
				testType: serverTest,
				name:     "SRTP-Server-" + ver.name,
				config: Config{
					MaxVersion:             ver.version,
					SRTPProtectionProfiles: []uint16{40, SRTP_AES128_CM_HMAC_SHA1_80, 42},
				},
				flags: []string{
					"-srtp-profiles",
					"SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32",
				},
				expectedSRTPProtectionProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			})
			// Test that the MKI is ignored.
			testCases = append(testCases, testCase{
				protocol: dtls,
				testType: serverTest,
				name:     "SRTP-Server-IgnoreMKI-" + ver.name,
				config: Config{
					MaxVersion:             ver.version,
					SRTPProtectionProfiles: []uint16{SRTP_AES128_CM_HMAC_SHA1_80},
					Bugs: ProtocolBugs{
						SRTPMasterKeyIdentifer: "bogus",
					},
				},
				flags: []string{
					"-srtp-profiles",
					"SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32",
				},
				expectedSRTPProtectionProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			})
			// Test that SRTP isn't negotiated on the server if there were
			// no matching profiles.
			testCases = append(testCases, testCase{
				protocol: dtls,
				testType: serverTest,
				name:     "SRTP-Server-NoMatch-" + ver.name,
				config: Config{
					MaxVersion:             ver.version,
					SRTPProtectionProfiles: []uint16{100, 101, 102},
				},
				flags: []string{
					"-srtp-profiles",
					"SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32",
				},
				expectedSRTPProtectionProfile: 0,
			})
			// Test that the server returning an invalid SRTP profile is
			// flagged as an error by the client.
			testCases = append(testCases, testCase{
				protocol: dtls,
				name:     "SRTP-Client-NoMatch-" + ver.name,
				config: Config{
					MaxVersion: ver.version,
					Bugs: ProtocolBugs{
						SendSRTPProtectionProfile: SRTP_AES128_CM_HMAC_SHA1_32,
					},
				},
				flags: []string{
					"-srtp-profiles",
					"SRTP_AES128_CM_SHA1_80",
				},
				shouldFail:    true,
				expectedError: ":BAD_SRTP_PROTECTION_PROFILE_LIST:",
			})
		}

		// Test SCT list.
		testCases = append(testCases, testCase{
			name:     "SignedCertificateTimestampList-Client-" + ver.name,
			testType: clientTest,
			config: Config{
				MaxVersion: ver.version,
			},
			flags: []string{
				"-enable-signed-cert-timestamps",
				"-expect-signed-cert-timestamps",
				base64.StdEncoding.EncodeToString(testSCTList),
			},
			resumeSession: resumeSession,
		})
		testCases = append(testCases, testCase{
			name: "SendSCTListOnResume-" + ver.name,
			config: Config{
				MaxVersion: ver.version,
				Bugs: ProtocolBugs{
					SendSCTListOnResume: []byte("bogus"),
				},
			},
			flags: []string{
				"-enable-signed-cert-timestamps",
				"-expect-signed-cert-timestamps",
				base64.StdEncoding.EncodeToString(testSCTList),
			},
			resumeSession: resumeSession,
		})
		testCases = append(testCases, testCase{
			name:     "SignedCertificateTimestampList-Server-" + ver.name,
			testType: serverTest,
			config: Config{
				MaxVersion: ver.version,
			},
			flags: []string{
				"-signed-cert-timestamps",
				base64.StdEncoding.EncodeToString(testSCTList),
			},
			expectedSCTList: testSCTList,
			resumeSession:   resumeSession,
		})
	}

	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "ClientHelloPadding",
		config: Config{
			Bugs: ProtocolBugs{
				RequireClientHelloSize: 512,
			},
		},
		// This hostname just needs to be long enough to push the
		// ClientHello into F5's danger zone between 256 and 511 bytes
		// long.
		flags: []string{"-host-name", "01234567890123456789012345678901234567890123456789012345678901234567890123456789.com"},
	})

	// Extensions should not function in SSL 3.0.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SSLv3Extensions-NoALPN",
		config: Config{
			MaxVersion: VersionSSL30,
			NextProtos: []string{"foo", "bar", "baz"},
		},
		flags: []string{
			"-select-alpn", "foo",
		},
		expectNoNextProto: true,
	})

	// Test session tickets separately as they follow a different codepath.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SSLv3Extensions-NoTickets",
		config: Config{
			MaxVersion: VersionSSL30,
			Bugs: ProtocolBugs{
				// Historically, session tickets in SSL 3.0
				// failed in different ways depending on whether
				// the client supported renegotiation_info.
				NoRenegotiationInfo: true,
			},
		},
		resumeSession: true,
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SSLv3Extensions-NoTickets2",
		config: Config{
			MaxVersion: VersionSSL30,
		},
		resumeSession: true,
	})

	// But SSL 3.0 does send and process renegotiation_info.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SSLv3Extensions-RenegotiationInfo",
		config: Config{
			MaxVersion: VersionSSL30,
			Bugs: ProtocolBugs{
				RequireRenegotiationInfo: true,
			},
		},
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SSLv3Extensions-RenegotiationInfo-SCSV",
		config: Config{
			MaxVersion: VersionSSL30,
			Bugs: ProtocolBugs{
				NoRenegotiationInfo:      true,
				SendRenegotiationSCSV:    true,
				RequireRenegotiationInfo: true,
			},
		},
	})

	// Test that illegal extensions in TLS 1.3 are rejected by the client if
	// in ServerHello.
	testCases = append(testCases, testCase{
		name: "NPN-Forbidden-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			NextProtos: []string{"foo"},
			Bugs: ProtocolBugs{
				NegotiateNPNAtAllVersions: true,
			},
		},
		flags:         []string{"-select-next-proto", "foo"},
		shouldFail:    true,
		expectedError: ":ERROR_PARSING_EXTENSION:",
	})
	testCases = append(testCases, testCase{
		name: "EMS-Forbidden-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				NegotiateEMSAtAllVersions: true,
			},
		},
		shouldFail:    true,
		expectedError: ":ERROR_PARSING_EXTENSION:",
	})
	testCases = append(testCases, testCase{
		name: "RenegotiationInfo-Forbidden-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				NegotiateRenegotiationInfoAtAllVersions: true,
			},
		},
		shouldFail:    true,
		expectedError: ":ERROR_PARSING_EXTENSION:",
	})
	testCases = append(testCases, testCase{
		name: "ChannelID-Forbidden-TLS13",
		config: Config{
			MaxVersion:       VersionTLS13,
			RequestChannelID: true,
			Bugs: ProtocolBugs{
				NegotiateChannelIDAtAllVersions: true,
			},
		},
		flags:         []string{"-send-channel-id", path.Join(*resourceDir, channelIDKeyFile)},
		shouldFail:    true,
		expectedError: ":ERROR_PARSING_EXTENSION:",
	})
	testCases = append(testCases, testCase{
		name: "Ticket-Forbidden-TLS13",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		resumeConfig: &Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				AdvertiseTicketExtension: true,
			},
		},
		resumeSession: true,
		shouldFail:    true,
		expectedError: ":ERROR_PARSING_EXTENSION:",
	})

	// Test that illegal extensions in TLS 1.3 are declined by the server if
	// offered in ClientHello. The runner's server will fail if this occurs,
	// so we exercise the offering path. (EMS and Renegotiation Info are
	// implicit in every test.)
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ChannelID-Declined-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			ChannelID:  channelIDKey,
		},
		flags: []string{"-enable-channel-id"},
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "NPN-Server",
		config: Config{
			MaxVersion: VersionTLS13,
			NextProtos: []string{"bar"},
		},
		flags: []string{"-advertise-npn", "\x03foo\x03bar\x03baz"},
	})
}

func addResumptionVersionTests() {
	for _, sessionVers := range tlsVersions {
		// TODO(davidben,svaldez): Implement resumption in TLS 1.3.
		if sessionVers.version >= VersionTLS13 {
			continue
		}
		for _, resumeVers := range tlsVersions {
			if resumeVers.version >= VersionTLS13 {
				continue
			}
			cipher := TLS_RSA_WITH_AES_128_CBC_SHA
			if sessionVers.version >= VersionTLS13 || resumeVers.version >= VersionTLS13 {
				// TLS 1.3 only shares ciphers with TLS 1.2, so
				// we skip certain combinations and use a
				// different cipher to test with.
				cipher = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				if sessionVers.version < VersionTLS12 || resumeVers.version < VersionTLS12 {
					continue
				}
			}

			protocols := []protocol{tls}
			if sessionVers.hasDTLS && resumeVers.hasDTLS {
				protocols = append(protocols, dtls)
			}
			for _, protocol := range protocols {
				suffix := "-" + sessionVers.name + "-" + resumeVers.name
				if protocol == dtls {
					suffix += "-DTLS"
				}

				if sessionVers.version == resumeVers.version {
					testCases = append(testCases, testCase{
						protocol:      protocol,
						name:          "Resume-Client" + suffix,
						resumeSession: true,
						config: Config{
							MaxVersion:   sessionVers.version,
							CipherSuites: []uint16{cipher},
						},
						expectedVersion:       sessionVers.version,
						expectedResumeVersion: resumeVers.version,
					})
				} else {
					testCases = append(testCases, testCase{
						protocol:      protocol,
						name:          "Resume-Client-Mismatch" + suffix,
						resumeSession: true,
						config: Config{
							MaxVersion:   sessionVers.version,
							CipherSuites: []uint16{cipher},
						},
						expectedVersion: sessionVers.version,
						resumeConfig: &Config{
							MaxVersion:   resumeVers.version,
							CipherSuites: []uint16{cipher},
							Bugs: ProtocolBugs{
								AllowSessionVersionMismatch: true,
							},
						},
						expectedResumeVersion: resumeVers.version,
						shouldFail:            true,
						expectedError:         ":OLD_SESSION_VERSION_NOT_RETURNED:",
					})
				}

				testCases = append(testCases, testCase{
					protocol:      protocol,
					name:          "Resume-Client-NoResume" + suffix,
					resumeSession: true,
					config: Config{
						MaxVersion:   sessionVers.version,
						CipherSuites: []uint16{cipher},
					},
					expectedVersion: sessionVers.version,
					resumeConfig: &Config{
						MaxVersion:   resumeVers.version,
						CipherSuites: []uint16{cipher},
					},
					newSessionsOnResume:   true,
					expectResumeRejected:  true,
					expectedResumeVersion: resumeVers.version,
				})

				testCases = append(testCases, testCase{
					protocol:      protocol,
					testType:      serverTest,
					name:          "Resume-Server" + suffix,
					resumeSession: true,
					config: Config{
						MaxVersion:   sessionVers.version,
						CipherSuites: []uint16{cipher},
					},
					expectedVersion:      sessionVers.version,
					expectResumeRejected: sessionVers.version != resumeVers.version,
					resumeConfig: &Config{
						MaxVersion:   resumeVers.version,
						CipherSuites: []uint16{cipher},
					},
					expectedResumeVersion: resumeVers.version,
				})
			}
		}
	}

	// TODO(davidben): This test should have a TLS 1.3 variant later.
	testCases = append(testCases, testCase{
		name:          "Resume-Client-CipherMismatch",
		resumeSession: true,
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
		},
		resumeConfig: &Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				SendCipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA,
			},
		},
		shouldFail:    true,
		expectedError: ":OLD_SESSION_CIPHER_NOT_RETURNED:",
	})
}

func addRenegotiationTests() {
	// Servers cannot renegotiate.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "Renegotiate-Server-Forbidden",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		renegotiate:        1,
		shouldFail:         true,
		expectedError:      ":NO_RENEGOTIATION:",
		expectedLocalError: "remote error: no renegotiation",
	})
	// The server shouldn't echo the renegotiation extension unless
	// requested by the client.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "Renegotiate-Server-NoExt",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				NoRenegotiationInfo:      true,
				RequireRenegotiationInfo: true,
			},
		},
		shouldFail:         true,
		expectedLocalError: "renegotiation extension missing",
	})
	// The renegotiation SCSV should be sufficient for the server to echo
	// the extension.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "Renegotiate-Server-NoExt-SCSV",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				NoRenegotiationInfo:      true,
				SendRenegotiationSCSV:    true,
				RequireRenegotiationInfo: true,
			},
		},
	})
	testCases = append(testCases, testCase{
		name: "Renegotiate-Client",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				FailIfResumeOnRenego: true,
			},
		},
		renegotiate: 1,
		flags: []string{
			"-renegotiate-freely",
			"-expect-total-renegotiations", "1",
		},
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-EmptyExt",
		renegotiate: 1,
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				EmptyRenegotiationInfo: true,
			},
		},
		flags:         []string{"-renegotiate-freely"},
		shouldFail:    true,
		expectedError: ":RENEGOTIATION_MISMATCH:",
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-BadExt",
		renegotiate: 1,
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				BadRenegotiationInfo: true,
			},
		},
		flags:         []string{"-renegotiate-freely"},
		shouldFail:    true,
		expectedError: ":RENEGOTIATION_MISMATCH:",
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-Downgrade",
		renegotiate: 1,
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				NoRenegotiationInfoAfterInitial: true,
			},
		},
		flags:         []string{"-renegotiate-freely"},
		shouldFail:    true,
		expectedError: ":RENEGOTIATION_MISMATCH:",
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-Upgrade",
		renegotiate: 1,
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				NoRenegotiationInfoInInitial: true,
			},
		},
		flags:         []string{"-renegotiate-freely"},
		shouldFail:    true,
		expectedError: ":RENEGOTIATION_MISMATCH:",
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-NoExt-Allowed",
		renegotiate: 1,
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				NoRenegotiationInfo: true,
			},
		},
		flags: []string{
			"-renegotiate-freely",
			"-expect-total-renegotiations", "1",
		},
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-SwitchCiphers",
		renegotiate: 1,
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA},
		},
		renegotiateCiphers: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		flags: []string{
			"-renegotiate-freely",
			"-expect-total-renegotiations", "1",
		},
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-SwitchCiphers2",
		renegotiate: 1,
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		renegotiateCiphers: []uint16{TLS_RSA_WITH_RC4_128_SHA},
		flags: []string{
			"-renegotiate-freely",
			"-expect-total-renegotiations", "1",
		},
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-SameClientVersion",
		renegotiate: 1,
		config: Config{
			MaxVersion: VersionTLS10,
			Bugs: ProtocolBugs{
				RequireSameRenegoClientVersion: true,
			},
		},
		flags: []string{
			"-renegotiate-freely",
			"-expect-total-renegotiations", "1",
		},
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-FalseStart",
		renegotiate: 1,
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			NextProtos:   []string{"foo"},
		},
		flags: []string{
			"-false-start",
			"-select-next-proto", "foo",
			"-renegotiate-freely",
			"-expect-total-renegotiations", "1",
		},
		shimWritesFirst: true,
	})

	// Client-side renegotiation controls.
	testCases = append(testCases, testCase{
		name: "Renegotiate-Client-Forbidden-1",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		renegotiate:        1,
		shouldFail:         true,
		expectedError:      ":NO_RENEGOTIATION:",
		expectedLocalError: "remote error: no renegotiation",
	})
	testCases = append(testCases, testCase{
		name: "Renegotiate-Client-Once-1",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		renegotiate: 1,
		flags: []string{
			"-renegotiate-once",
			"-expect-total-renegotiations", "1",
		},
	})
	testCases = append(testCases, testCase{
		name: "Renegotiate-Client-Freely-1",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		renegotiate: 1,
		flags: []string{
			"-renegotiate-freely",
			"-expect-total-renegotiations", "1",
		},
	})
	testCases = append(testCases, testCase{
		name: "Renegotiate-Client-Once-2",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		renegotiate:        2,
		flags:              []string{"-renegotiate-once"},
		shouldFail:         true,
		expectedError:      ":NO_RENEGOTIATION:",
		expectedLocalError: "remote error: no renegotiation",
	})
	testCases = append(testCases, testCase{
		name: "Renegotiate-Client-Freely-2",
		config: Config{
			MaxVersion: VersionTLS12,
		},
		renegotiate: 2,
		flags: []string{
			"-renegotiate-freely",
			"-expect-total-renegotiations", "2",
		},
	})
	testCases = append(testCases, testCase{
		name: "Renegotiate-Client-NoIgnore",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				SendHelloRequestBeforeEveryAppDataRecord: true,
			},
		},
		shouldFail:    true,
		expectedError: ":NO_RENEGOTIATION:",
	})
	testCases = append(testCases, testCase{
		name: "Renegotiate-Client-Ignore",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				SendHelloRequestBeforeEveryAppDataRecord: true,
			},
		},
		flags: []string{
			"-renegotiate-ignore",
			"-expect-total-renegotiations", "0",
		},
	})

	// Stray HelloRequests during the handshake are ignored in TLS 1.2.
	testCases = append(testCases, testCase{
		name: "StrayHelloRequest",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				SendHelloRequestBeforeEveryHandshakeMessage: true,
			},
		},
	})
	testCases = append(testCases, testCase{
		name: "StrayHelloRequest-Packed",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				PackHandshakeFlight:                         true,
				SendHelloRequestBeforeEveryHandshakeMessage: true,
			},
		},
	})

	// Renegotiation is forbidden in TLS 1.3.
	//
	// TODO(davidben): This test current asserts that we ignore
	// HelloRequests, but we actually should hard reject them. Fix this
	// test once we actually parse post-handshake messages.
	testCases = append(testCases, testCase{
		name: "Renegotiate-Client-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SendHelloRequestBeforeEveryAppDataRecord: true,
			},
		},
		flags: []string{
			"-renegotiate-freely",
		},
	})

	// Stray HelloRequests during the handshake are forbidden in TLS 1.3.
	testCases = append(testCases, testCase{
		name: "StrayHelloRequest-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SendHelloRequestBeforeEveryHandshakeMessage: true,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
	})
}

func addDTLSReplayTests() {
	// Test that sequence number replays are detected.
	testCases = append(testCases, testCase{
		protocol:     dtls,
		name:         "DTLS-Replay",
		messageCount: 200,
		replayWrites: true,
	})

	// Test the incoming sequence number skipping by values larger
	// than the retransmit window.
	testCases = append(testCases, testCase{
		protocol: dtls,
		name:     "DTLS-Replay-LargeGaps",
		config: Config{
			Bugs: ProtocolBugs{
				SequenceNumberMapping: func(in uint64) uint64 {
					return in * 127
				},
			},
		},
		messageCount: 200,
		replayWrites: true,
	})

	// Test the incoming sequence number changing non-monotonically.
	testCases = append(testCases, testCase{
		protocol: dtls,
		name:     "DTLS-Replay-NonMonotonic",
		config: Config{
			Bugs: ProtocolBugs{
				SequenceNumberMapping: func(in uint64) uint64 {
					return in ^ 31
				},
			},
		},
		messageCount: 200,
		replayWrites: true,
	})
}

var testSignatureAlgorithms = []struct {
	name string
	id   signatureAlgorithm
	cert testCert
}{
	{"RSA-PKCS1-SHA1", signatureRSAPKCS1WithSHA1, testCertRSA},
	{"RSA-PKCS1-SHA256", signatureRSAPKCS1WithSHA256, testCertRSA},
	{"RSA-PKCS1-SHA384", signatureRSAPKCS1WithSHA384, testCertRSA},
	{"RSA-PKCS1-SHA512", signatureRSAPKCS1WithSHA512, testCertRSA},
	{"ECDSA-SHA1", signatureECDSAWithSHA1, testCertECDSAP256},
	{"ECDSA-P256-SHA256", signatureECDSAWithP256AndSHA256, testCertECDSAP256},
	{"ECDSA-P384-SHA384", signatureECDSAWithP384AndSHA384, testCertECDSAP384},
	{"ECDSA-P521-SHA512", signatureECDSAWithP521AndSHA512, testCertECDSAP521},
	{"RSA-PSS-SHA256", signatureRSAPSSWithSHA256, testCertRSA},
	{"RSA-PSS-SHA384", signatureRSAPSSWithSHA384, testCertRSA},
	{"RSA-PSS-SHA512", signatureRSAPSSWithSHA512, testCertRSA},
	// Tests for key types prior to TLS 1.2.
	{"RSA", 0, testCertRSA},
	{"ECDSA", 0, testCertECDSAP256},
}

const fakeSigAlg1 signatureAlgorithm = 0x2a01
const fakeSigAlg2 signatureAlgorithm = 0xff01

func addSignatureAlgorithmTests() {
	// Not all ciphers involve a signature. Advertise a list which gives all
	// versions a signing cipher.
	signingCiphers := []uint16{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	}

	var allAlgorithms []signatureAlgorithm
	for _, alg := range testSignatureAlgorithms {
		if alg.id != 0 {
			allAlgorithms = append(allAlgorithms, alg.id)
		}
	}

	// Make sure each signature algorithm works. Include some fake values in
	// the list and ensure they're ignored.
	for _, alg := range testSignatureAlgorithms {
		for _, ver := range tlsVersions {
			if (ver.version < VersionTLS12) != (alg.id == 0) {
				continue
			}

			// TODO(davidben): Support ECDSA in SSL 3.0 in Go for testing
			// or remove it in C.
			if ver.version == VersionSSL30 && alg.cert != testCertRSA {
				continue
			}

			var shouldFail bool
			// ecdsa_sha1 does not exist in TLS 1.3.
			if ver.version >= VersionTLS13 && alg.id == signatureECDSAWithSHA1 {
				shouldFail = true
			}
			// RSA-PSS does not exist in TLS 1.2.
			if ver.version == VersionTLS12 && hasComponent(alg.name, "PSS") {
				shouldFail = true
			}

			var signError, verifyError string
			if shouldFail {
				signError = ":NO_COMMON_SIGNATURE_ALGORITHMS:"
				verifyError = ":WRONG_SIGNATURE_TYPE:"
			}

			suffix := "-" + alg.name + "-" + ver.name

			testCases = append(testCases, testCase{
				name: "ClientAuth-Sign" + suffix,
				config: Config{
					MaxVersion: ver.version,
					ClientAuth: RequireAnyClientCert,
					VerifySignatureAlgorithms: []signatureAlgorithm{
						fakeSigAlg1,
						alg.id,
						fakeSigAlg2,
					},
				},
				flags: []string{
					"-cert-file", path.Join(*resourceDir, getShimCertificate(alg.cert)),
					"-key-file", path.Join(*resourceDir, getShimKey(alg.cert)),
					"-enable-all-curves",
				},
				shouldFail:                     shouldFail,
				expectedError:                  signError,
				expectedPeerSignatureAlgorithm: alg.id,
			})

			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     "ClientAuth-Verify" + suffix,
				config: Config{
					MaxVersion:   ver.version,
					Certificates: []Certificate{getRunnerCertificate(alg.cert)},
					SignSignatureAlgorithms: []signatureAlgorithm{
						alg.id,
					},
					Bugs: ProtocolBugs{
						SkipECDSACurveCheck:          shouldFail,
						IgnoreSignatureVersionChecks: shouldFail,
						// The client won't advertise 1.3-only algorithms after
						// version negotiation.
						IgnorePeerSignatureAlgorithmPreferences: shouldFail,
					},
				},
				flags: []string{
					"-require-any-client-certificate",
					"-expect-peer-signature-algorithm", strconv.Itoa(int(alg.id)),
					"-enable-all-curves",
				},
				shouldFail:    shouldFail,
				expectedError: verifyError,
			})

			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     "ServerAuth-Sign" + suffix,
				config: Config{
					MaxVersion:   ver.version,
					CipherSuites: signingCiphers,
					VerifySignatureAlgorithms: []signatureAlgorithm{
						fakeSigAlg1,
						alg.id,
						fakeSigAlg2,
					},
				},
				flags: []string{
					"-cert-file", path.Join(*resourceDir, getShimCertificate(alg.cert)),
					"-key-file", path.Join(*resourceDir, getShimKey(alg.cert)),
					"-enable-all-curves",
				},
				shouldFail:                     shouldFail,
				expectedError:                  signError,
				expectedPeerSignatureAlgorithm: alg.id,
			})

			testCases = append(testCases, testCase{
				name: "ServerAuth-Verify" + suffix,
				config: Config{
					MaxVersion:   ver.version,
					Certificates: []Certificate{getRunnerCertificate(alg.cert)},
					CipherSuites: signingCiphers,
					SignSignatureAlgorithms: []signatureAlgorithm{
						alg.id,
					},
					Bugs: ProtocolBugs{
						SkipECDSACurveCheck:          shouldFail,
						IgnoreSignatureVersionChecks: shouldFail,
					},
				},
				flags: []string{
					"-expect-peer-signature-algorithm", strconv.Itoa(int(alg.id)),
					"-enable-all-curves",
				},
				shouldFail:    shouldFail,
				expectedError: verifyError,
			})

			if !shouldFail {
				testCases = append(testCases, testCase{
					testType: serverTest,
					name:     "ClientAuth-InvalidSignature" + suffix,
					config: Config{
						MaxVersion:   ver.version,
						Certificates: []Certificate{getRunnerCertificate(alg.cert)},
						SignSignatureAlgorithms: []signatureAlgorithm{
							alg.id,
						},
						Bugs: ProtocolBugs{
							InvalidSignature: true,
						},
					},
					flags: []string{
						"-require-any-client-certificate",
						"-enable-all-curves",
					},
					shouldFail:    true,
					expectedError: ":BAD_SIGNATURE:",
				})

				testCases = append(testCases, testCase{
					name: "ServerAuth-InvalidSignature" + suffix,
					config: Config{
						MaxVersion:   ver.version,
						Certificates: []Certificate{getRunnerCertificate(alg.cert)},
						CipherSuites: signingCiphers,
						SignSignatureAlgorithms: []signatureAlgorithm{
							alg.id,
						},
						Bugs: ProtocolBugs{
							InvalidSignature: true,
						},
					},
					flags:         []string{"-enable-all-curves"},
					shouldFail:    true,
					expectedError: ":BAD_SIGNATURE:",
				})
			}

			if ver.version >= VersionTLS12 && !shouldFail {
				testCases = append(testCases, testCase{
					name: "ClientAuth-Sign-Negotiate" + suffix,
					config: Config{
						MaxVersion:                ver.version,
						ClientAuth:                RequireAnyClientCert,
						VerifySignatureAlgorithms: allAlgorithms,
					},
					flags: []string{
						"-cert-file", path.Join(*resourceDir, getShimCertificate(alg.cert)),
						"-key-file", path.Join(*resourceDir, getShimKey(alg.cert)),
						"-enable-all-curves",
						"-signing-prefs", strconv.Itoa(int(alg.id)),
					},
					expectedPeerSignatureAlgorithm: alg.id,
				})

				testCases = append(testCases, testCase{
					testType: serverTest,
					name:     "ServerAuth-Sign-Negotiate" + suffix,
					config: Config{
						MaxVersion:                ver.version,
						CipherSuites:              signingCiphers,
						VerifySignatureAlgorithms: allAlgorithms,
					},
					flags: []string{
						"-cert-file", path.Join(*resourceDir, getShimCertificate(alg.cert)),
						"-key-file", path.Join(*resourceDir, getShimKey(alg.cert)),
						"-enable-all-curves",
						"-signing-prefs", strconv.Itoa(int(alg.id)),
					},
					expectedPeerSignatureAlgorithm: alg.id,
				})
			}
		}
	}

	// Test that algorithm selection takes the key type into account.
	testCases = append(testCases, testCase{
		name: "ClientAuth-SignatureType",
		config: Config{
			ClientAuth: RequireAnyClientCert,
			MaxVersion: VersionTLS12,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureECDSAWithP521AndSHA512,
				signatureRSAPKCS1WithSHA384,
				signatureECDSAWithSHA1,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
		},
		expectedPeerSignatureAlgorithm: signatureRSAPKCS1WithSHA384,
	})

	testCases = append(testCases, testCase{
		name: "ClientAuth-SignatureType-TLS13",
		config: Config{
			ClientAuth: RequireAnyClientCert,
			MaxVersion: VersionTLS13,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureECDSAWithP521AndSHA512,
				signatureRSAPKCS1WithSHA384,
				signatureRSAPSSWithSHA384,
				signatureECDSAWithSHA1,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
		},
		expectedPeerSignatureAlgorithm: signatureRSAPSSWithSHA384,
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ServerAuth-SignatureType",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureECDSAWithP521AndSHA512,
				signatureRSAPKCS1WithSHA384,
				signatureECDSAWithSHA1,
			},
		},
		expectedPeerSignatureAlgorithm: signatureRSAPKCS1WithSHA384,
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ServerAuth-SignatureType-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureECDSAWithP521AndSHA512,
				signatureRSAPKCS1WithSHA384,
				signatureRSAPSSWithSHA384,
				signatureECDSAWithSHA1,
			},
		},
		expectedPeerSignatureAlgorithm: signatureRSAPSSWithSHA384,
	})

	// Test that signature verification takes the key type into account.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "Verify-ClientAuth-SignatureType",
		config: Config{
			MaxVersion:   VersionTLS12,
			Certificates: []Certificate{rsaCertificate},
			SignSignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA256,
			},
			Bugs: ProtocolBugs{
				SendSignatureAlgorithm: signatureECDSAWithP256AndSHA256,
			},
		},
		flags: []string{
			"-require-any-client-certificate",
		},
		shouldFail:    true,
		expectedError: ":WRONG_SIGNATURE_TYPE:",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "Verify-ClientAuth-SignatureType-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			Certificates: []Certificate{rsaCertificate},
			SignSignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPSSWithSHA256,
			},
			Bugs: ProtocolBugs{
				SendSignatureAlgorithm: signatureECDSAWithP256AndSHA256,
			},
		},
		flags: []string{
			"-require-any-client-certificate",
		},
		shouldFail:    true,
		expectedError: ":WRONG_SIGNATURE_TYPE:",
	})

	testCases = append(testCases, testCase{
		name: "Verify-ServerAuth-SignatureType",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			SignSignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA256,
			},
			Bugs: ProtocolBugs{
				SendSignatureAlgorithm: signatureECDSAWithP256AndSHA256,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_SIGNATURE_TYPE:",
	})

	testCases = append(testCases, testCase{
		name: "Verify-ServerAuth-SignatureType-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			SignSignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPSSWithSHA256,
			},
			Bugs: ProtocolBugs{
				SendSignatureAlgorithm: signatureECDSAWithP256AndSHA256,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_SIGNATURE_TYPE:",
	})

	// Test that, if the list is missing, the peer falls back to SHA-1 in
	// TLS 1.2, but not TLS 1.3.
	testCases = append(testCases, testCase{
		name: "ClientAuth-SHA1-Fallback",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequireAnyClientCert,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA1,
			},
			Bugs: ProtocolBugs{
				NoSignatureAlgorithms: true,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
		},
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ServerAuth-SHA1-Fallback",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA1,
			},
			Bugs: ProtocolBugs{
				NoSignatureAlgorithms: true,
			},
		},
	})

	testCases = append(testCases, testCase{
		name: "ClientAuth-NoFallback-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			ClientAuth: RequireAnyClientCert,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA1,
			},
			Bugs: ProtocolBugs{
				NoSignatureAlgorithms: true,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
		},
		shouldFail:    true,
		expectedError: ":NO_COMMON_SIGNATURE_ALGORITHMS:",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ServerAuth-NoFallback-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA1,
			},
			Bugs: ProtocolBugs{
				NoSignatureAlgorithms: true,
			},
		},
		shouldFail:    true,
		expectedError: ":NO_COMMON_SIGNATURE_ALGORITHMS:",
	})

	// Test that hash preferences are enforced. BoringSSL does not implement
	// MD5 signatures.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ClientAuth-Enforced",
		config: Config{
			MaxVersion:   VersionTLS12,
			Certificates: []Certificate{rsaCertificate},
			SignSignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithMD5,
			},
			Bugs: ProtocolBugs{
				IgnorePeerSignatureAlgorithmPreferences: true,
			},
		},
		flags:         []string{"-require-any-client-certificate"},
		shouldFail:    true,
		expectedError: ":WRONG_SIGNATURE_TYPE:",
	})

	testCases = append(testCases, testCase{
		name: "ServerAuth-Enforced",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			SignSignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithMD5,
			},
			Bugs: ProtocolBugs{
				IgnorePeerSignatureAlgorithmPreferences: true,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_SIGNATURE_TYPE:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ClientAuth-Enforced-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			Certificates: []Certificate{rsaCertificate},
			SignSignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithMD5,
			},
			Bugs: ProtocolBugs{
				IgnorePeerSignatureAlgorithmPreferences: true,
				IgnoreSignatureVersionChecks:            true,
			},
		},
		flags:         []string{"-require-any-client-certificate"},
		shouldFail:    true,
		expectedError: ":WRONG_SIGNATURE_TYPE:",
	})

	testCases = append(testCases, testCase{
		name: "ServerAuth-Enforced-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			SignSignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithMD5,
			},
			Bugs: ProtocolBugs{
				IgnorePeerSignatureAlgorithmPreferences: true,
				IgnoreSignatureVersionChecks:            true,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_SIGNATURE_TYPE:",
	})

	// Test that the agreed upon digest respects the client preferences and
	// the server digests.
	testCases = append(testCases, testCase{
		name: "NoCommonAlgorithms-Digests",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequireAnyClientCert,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA512,
				signatureRSAPKCS1WithSHA1,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
			"-digest-prefs", "SHA256",
		},
		shouldFail:    true,
		expectedError: ":NO_COMMON_SIGNATURE_ALGORITHMS:",
	})
	testCases = append(testCases, testCase{
		name: "NoCommonAlgorithms",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequireAnyClientCert,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA512,
				signatureRSAPKCS1WithSHA1,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
			"-signing-prefs", strconv.Itoa(int(signatureRSAPKCS1WithSHA256)),
		},
		shouldFail:    true,
		expectedError: ":NO_COMMON_SIGNATURE_ALGORITHMS:",
	})
	testCases = append(testCases, testCase{
		name: "NoCommonAlgorithms-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			ClientAuth: RequireAnyClientCert,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPSSWithSHA512,
				signatureRSAPSSWithSHA384,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
			"-signing-prefs", strconv.Itoa(int(signatureRSAPSSWithSHA256)),
		},
		shouldFail:    true,
		expectedError: ":NO_COMMON_SIGNATURE_ALGORITHMS:",
	})
	testCases = append(testCases, testCase{
		name: "Agree-Digest-SHA256",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequireAnyClientCert,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA1,
				signatureRSAPKCS1WithSHA256,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
			"-digest-prefs", "SHA256,SHA1",
		},
		expectedPeerSignatureAlgorithm: signatureRSAPKCS1WithSHA256,
	})
	testCases = append(testCases, testCase{
		name: "Agree-Digest-SHA1",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequireAnyClientCert,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA1,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
			"-digest-prefs", "SHA512,SHA256,SHA1",
		},
		expectedPeerSignatureAlgorithm: signatureRSAPKCS1WithSHA1,
	})
	testCases = append(testCases, testCase{
		name: "Agree-Digest-Default",
		config: Config{
			MaxVersion: VersionTLS12,
			ClientAuth: RequireAnyClientCert,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA256,
				signatureECDSAWithP256AndSHA256,
				signatureRSAPKCS1WithSHA1,
				signatureECDSAWithSHA1,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
		},
		expectedPeerSignatureAlgorithm: signatureRSAPKCS1WithSHA256,
	})

	// Test that the signing preference list may include extra algorithms
	// without negotiation problems.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "FilterExtraAlgorithms",
		config: Config{
			MaxVersion: VersionTLS12,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPKCS1WithSHA256,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsaCertificateFile),
			"-key-file", path.Join(*resourceDir, rsaKeyFile),
			"-signing-prefs", strconv.Itoa(int(fakeSigAlg1)),
			"-signing-prefs", strconv.Itoa(int(signatureECDSAWithP256AndSHA256)),
			"-signing-prefs", strconv.Itoa(int(signatureRSAPKCS1WithSHA256)),
			"-signing-prefs", strconv.Itoa(int(fakeSigAlg2)),
		},
		expectedPeerSignatureAlgorithm: signatureRSAPKCS1WithSHA256,
	})

	// In TLS 1.2 and below, ECDSA uses the curve list rather than the
	// signature algorithms.
	testCases = append(testCases, testCase{
		name: "CheckLeafCurve",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			Certificates: []Certificate{ecdsaP256Certificate},
		},
		flags:         []string{"-p384-only"},
		shouldFail:    true,
		expectedError: ":BAD_ECC_CERT:",
	})

	// In TLS 1.3, ECDSA does not use the ECDHE curve list.
	testCases = append(testCases, testCase{
		name: "CheckLeafCurve-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			Certificates: []Certificate{ecdsaP256Certificate},
		},
		flags: []string{"-p384-only"},
	})

	// In TLS 1.2, the ECDSA curve is not in the signature algorithm.
	testCases = append(testCases, testCase{
		name: "ECDSACurveMismatch-Verify-TLS12",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			Certificates: []Certificate{ecdsaP256Certificate},
			SignSignatureAlgorithms: []signatureAlgorithm{
				signatureECDSAWithP384AndSHA384,
			},
		},
	})

	// In TLS 1.3, the ECDSA curve comes from the signature algorithm.
	testCases = append(testCases, testCase{
		name: "ECDSACurveMismatch-Verify-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			Certificates: []Certificate{ecdsaP256Certificate},
			SignSignatureAlgorithms: []signatureAlgorithm{
				signatureECDSAWithP384AndSHA384,
			},
			Bugs: ProtocolBugs{
				SkipECDSACurveCheck: true,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_SIGNATURE_TYPE:",
	})

	// Signature algorithm selection in TLS 1.3 should take the curve into
	// account.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ECDSACurveMismatch-Sign-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureECDSAWithP384AndSHA384,
				signatureECDSAWithP256AndSHA256,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, ecdsaP256CertificateFile),
			"-key-file", path.Join(*resourceDir, ecdsaP256KeyFile),
		},
		expectedPeerSignatureAlgorithm: signatureECDSAWithP256AndSHA256,
	})

	// RSASSA-PSS with SHA-512 is too large for 1024-bit RSA. Test that the
	// server does not attempt to sign in that case.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "RSA-PSS-Large",
		config: Config{
			MaxVersion: VersionTLS13,
			VerifySignatureAlgorithms: []signatureAlgorithm{
				signatureRSAPSSWithSHA512,
			},
		},
		flags: []string{
			"-cert-file", path.Join(*resourceDir, rsa1024CertificateFile),
			"-key-file", path.Join(*resourceDir, rsa1024KeyFile),
		},
		shouldFail:    true,
		expectedError: ":NO_COMMON_SIGNATURE_ALGORITHMS:",
	})
}

// timeouts is the retransmit schedule for BoringSSL. It doubles and
// caps at 60 seconds. On the 13th timeout, it gives up.
var timeouts = []time.Duration{
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	32 * time.Second,
	60 * time.Second,
	60 * time.Second,
	60 * time.Second,
	60 * time.Second,
	60 * time.Second,
	60 * time.Second,
	60 * time.Second,
}

// shortTimeouts is an alternate set of timeouts which would occur if the
// initial timeout duration was set to 250ms.
var shortTimeouts = []time.Duration{
	250 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	32 * time.Second,
	60 * time.Second,
	60 * time.Second,
	60 * time.Second,
	60 * time.Second,
	60 * time.Second,
}

func addDTLSRetransmitTests() {
	// These tests work by coordinating some behavior on both the shim and
	// the runner.
	//
	// TimeoutSchedule configures the runner to send a series of timeout
	// opcodes to the shim (see packetAdaptor) immediately before reading
	// each peer handshake flight N. The timeout opcode both simulates a
	// timeout in the shim and acts as a synchronization point to help the
	// runner bracket each handshake flight.
	//
	// We assume the shim does not read from the channel eagerly. It must
	// first wait until it has sent flight N and is ready to receive
	// handshake flight N+1. At this point, it will process the timeout
	// opcode. It must then immediately respond with a timeout ACK and act
	// as if the shim was idle for the specified amount of time.
	//
	// The runner then drops all packets received before the ACK and
	// continues waiting for flight N. This ordering results in one attempt
	// at sending flight N to be dropped. For the test to complete, the
	// shim must send flight N again, testing that the shim implements DTLS
	// retransmit on a timeout.

	// TODO(davidben): Add DTLS 1.3 versions of these tests. There will
	// likely be more epochs to cross and the final message's retransmit may
	// be more complex.

	for _, async := range []bool{true, false} {
		var tests []testCase

		// Test that this is indeed the timeout schedule. Stress all
		// four patterns of handshake.
		for i := 1; i < len(timeouts); i++ {
			number := strconv.Itoa(i)
			tests = append(tests, testCase{
				protocol: dtls,
				name:     "DTLS-Retransmit-Client-" + number,
				config: Config{
					MaxVersion: VersionTLS12,
					Bugs: ProtocolBugs{
						TimeoutSchedule: timeouts[:i],
					},
				},
				resumeSession: true,
			})
			tests = append(tests, testCase{
				protocol: dtls,
				testType: serverTest,
				name:     "DTLS-Retransmit-Server-" + number,
				config: Config{
					MaxVersion: VersionTLS12,
					Bugs: ProtocolBugs{
						TimeoutSchedule: timeouts[:i],
					},
				},
				resumeSession: true,
			})
		}

		// Test that exceeding the timeout schedule hits a read
		// timeout.
		tests = append(tests, testCase{
			protocol: dtls,
			name:     "DTLS-Retransmit-Timeout",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					TimeoutSchedule: timeouts,
				},
			},
			resumeSession: true,
			shouldFail:    true,
			expectedError: ":READ_TIMEOUT_EXPIRED:",
		})

		if async {
			// Test that timeout handling has a fudge factor, due to API
			// problems.
			tests = append(tests, testCase{
				protocol: dtls,
				name:     "DTLS-Retransmit-Fudge",
				config: Config{
					MaxVersion: VersionTLS12,
					Bugs: ProtocolBugs{
						TimeoutSchedule: []time.Duration{
							timeouts[0] - 10*time.Millisecond,
						},
					},
				},
				resumeSession: true,
			})
		}

		// Test that the final Finished retransmitting isn't
		// duplicated if the peer badly fragments everything.
		tests = append(tests, testCase{
			testType: serverTest,
			protocol: dtls,
			name:     "DTLS-Retransmit-Fragmented",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					TimeoutSchedule:          []time.Duration{timeouts[0]},
					MaxHandshakeRecordLength: 2,
				},
			},
		})

		// Test the timeout schedule when a shorter initial timeout duration is set.
		tests = append(tests, testCase{
			protocol: dtls,
			name:     "DTLS-Retransmit-Short-Client",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					TimeoutSchedule: shortTimeouts[:len(shortTimeouts)-1],
				},
			},
			resumeSession: true,
			flags:         []string{"-initial-timeout-duration-ms", "250"},
		})
		tests = append(tests, testCase{
			protocol: dtls,
			testType: serverTest,
			name:     "DTLS-Retransmit-Short-Server",
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					TimeoutSchedule: shortTimeouts[:len(shortTimeouts)-1],
				},
			},
			resumeSession: true,
			flags:         []string{"-initial-timeout-duration-ms", "250"},
		})

		for _, test := range tests {
			if async {
				test.name += "-Async"
				test.flags = append(test.flags, "-async")
			}

			testCases = append(testCases, test)
		}
	}
}

func addExportKeyingMaterialTests() {
	for _, vers := range tlsVersions {
		if vers.version == VersionSSL30 {
			continue
		}
		testCases = append(testCases, testCase{
			name: "ExportKeyingMaterial-" + vers.name,
			config: Config{
				MaxVersion: vers.version,
			},
			exportKeyingMaterial: 1024,
			exportLabel:          "label",
			exportContext:        "context",
			useExportContext:     true,
		})
		testCases = append(testCases, testCase{
			name: "ExportKeyingMaterial-NoContext-" + vers.name,
			config: Config{
				MaxVersion: vers.version,
			},
			exportKeyingMaterial: 1024,
		})
		testCases = append(testCases, testCase{
			name: "ExportKeyingMaterial-EmptyContext-" + vers.name,
			config: Config{
				MaxVersion: vers.version,
			},
			exportKeyingMaterial: 1024,
			useExportContext:     true,
		})
		testCases = append(testCases, testCase{
			name: "ExportKeyingMaterial-Small-" + vers.name,
			config: Config{
				MaxVersion: vers.version,
			},
			exportKeyingMaterial: 1,
			exportLabel:          "label",
			exportContext:        "context",
			useExportContext:     true,
		})
	}
	testCases = append(testCases, testCase{
		name: "ExportKeyingMaterial-SSL3",
		config: Config{
			MaxVersion: VersionSSL30,
		},
		exportKeyingMaterial: 1024,
		exportLabel:          "label",
		exportContext:        "context",
		useExportContext:     true,
		shouldFail:           true,
		expectedError:        "failed to export keying material",
	})
}

func addTLSUniqueTests() {
	for _, isClient := range []bool{false, true} {
		for _, isResumption := range []bool{false, true} {
			for _, hasEMS := range []bool{false, true} {
				var suffix string
				if isResumption {
					suffix = "Resume-"
				} else {
					suffix = "Full-"
				}

				if hasEMS {
					suffix += "EMS-"
				} else {
					suffix += "NoEMS-"
				}

				if isClient {
					suffix += "Client"
				} else {
					suffix += "Server"
				}

				test := testCase{
					name:          "TLSUnique-" + suffix,
					testTLSUnique: true,
					config: Config{
						MaxVersion: VersionTLS12,
						Bugs: ProtocolBugs{
							NoExtendedMasterSecret: !hasEMS,
						},
					},
				}

				if isResumption {
					test.resumeSession = true
					test.resumeConfig = &Config{
						MaxVersion: VersionTLS12,
						Bugs: ProtocolBugs{
							NoExtendedMasterSecret: !hasEMS,
						},
					}
				}

				if isResumption && !hasEMS {
					test.shouldFail = true
					test.expectedError = "failed to get tls-unique"
				}

				testCases = append(testCases, test)
			}
		}
	}
}

func addCustomExtensionTests() {
	expectedContents := "custom extension"
	emptyString := ""

	for _, isClient := range []bool{false, true} {
		suffix := "Server"
		flag := "-enable-server-custom-extension"
		testType := serverTest
		if isClient {
			suffix = "Client"
			flag = "-enable-client-custom-extension"
			testType = clientTest
		}

		testCases = append(testCases, testCase{
			testType: testType,
			name:     "CustomExtensions-" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					CustomExtension:         expectedContents,
					ExpectedCustomExtension: &expectedContents,
				},
			},
			flags: []string{flag},
		})
		testCases = append(testCases, testCase{
			testType: testType,
			name:     "CustomExtensions-" + suffix + "-TLS13",
			config: Config{
				MaxVersion: VersionTLS13,
				Bugs: ProtocolBugs{
					CustomExtension:         expectedContents,
					ExpectedCustomExtension: &expectedContents,
				},
			},
			flags: []string{flag},
		})

		// If the parse callback fails, the handshake should also fail.
		testCases = append(testCases, testCase{
			testType: testType,
			name:     "CustomExtensions-ParseError-" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					CustomExtension:         expectedContents + "foo",
					ExpectedCustomExtension: &expectedContents,
				},
			},
			flags:         []string{flag},
			shouldFail:    true,
			expectedError: ":CUSTOM_EXTENSION_ERROR:",
		})
		testCases = append(testCases, testCase{
			testType: testType,
			name:     "CustomExtensions-ParseError-" + suffix + "-TLS13",
			config: Config{
				MaxVersion: VersionTLS13,
				Bugs: ProtocolBugs{
					CustomExtension:         expectedContents + "foo",
					ExpectedCustomExtension: &expectedContents,
				},
			},
			flags:         []string{flag},
			shouldFail:    true,
			expectedError: ":CUSTOM_EXTENSION_ERROR:",
		})

		// If the add callback fails, the handshake should also fail.
		testCases = append(testCases, testCase{
			testType: testType,
			name:     "CustomExtensions-FailAdd-" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					CustomExtension:         expectedContents,
					ExpectedCustomExtension: &expectedContents,
				},
			},
			flags:         []string{flag, "-custom-extension-fail-add"},
			shouldFail:    true,
			expectedError: ":CUSTOM_EXTENSION_ERROR:",
		})
		testCases = append(testCases, testCase{
			testType: testType,
			name:     "CustomExtensions-FailAdd-" + suffix + "-TLS13",
			config: Config{
				MaxVersion: VersionTLS13,
				Bugs: ProtocolBugs{
					CustomExtension:         expectedContents,
					ExpectedCustomExtension: &expectedContents,
				},
			},
			flags:         []string{flag, "-custom-extension-fail-add"},
			shouldFail:    true,
			expectedError: ":CUSTOM_EXTENSION_ERROR:",
		})

		// If the add callback returns zero, no extension should be
		// added.
		skipCustomExtension := expectedContents
		if isClient {
			// For the case where the client skips sending the
			// custom extension, the server must not “echo” it.
			skipCustomExtension = ""
		}
		testCases = append(testCases, testCase{
			testType: testType,
			name:     "CustomExtensions-Skip-" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					CustomExtension:         skipCustomExtension,
					ExpectedCustomExtension: &emptyString,
				},
			},
			flags: []string{flag, "-custom-extension-skip"},
		})
		testCases = append(testCases, testCase{
			testType: testType,
			name:     "CustomExtensions-Skip-" + suffix + "-TLS13",
			config: Config{
				MaxVersion: VersionTLS13,
				Bugs: ProtocolBugs{
					CustomExtension:         skipCustomExtension,
					ExpectedCustomExtension: &emptyString,
				},
			},
			flags: []string{flag, "-custom-extension-skip"},
		})
	}

	// The custom extension add callback should not be called if the client
	// doesn't send the extension.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "CustomExtensions-NotCalled-Server",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				ExpectedCustomExtension: &emptyString,
			},
		},
		flags: []string{"-enable-server-custom-extension", "-custom-extension-fail-add"},
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "CustomExtensions-NotCalled-Server-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				ExpectedCustomExtension: &emptyString,
			},
		},
		flags: []string{"-enable-server-custom-extension", "-custom-extension-fail-add"},
	})

	// Test an unknown extension from the server.
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "UnknownExtension-Client",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				CustomExtension: expectedContents,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_EXTENSION:",
	})
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "UnknownExtension-Client-TLS13",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				CustomExtension: expectedContents,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_EXTENSION:",
	})
}

func addRSAClientKeyExchangeTests() {
	for bad := RSABadValue(1); bad < NumRSABadValues; bad++ {
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     fmt.Sprintf("BadRSAClientKeyExchange-%d", bad),
			config: Config{
				// Ensure the ClientHello version and final
				// version are different, to detect if the
				// server uses the wrong one.
				MaxVersion:   VersionTLS11,
				CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA},
				Bugs: ProtocolBugs{
					BadRSAClientKeyExchange: bad,
				},
			},
			shouldFail:    true,
			expectedError: ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
		})
	}
}

var testCurves = []struct {
	name string
	id   CurveID
}{
	{"P-256", CurveP256},
	{"P-384", CurveP384},
	{"P-521", CurveP521},
	{"X25519", CurveX25519},
}

const bogusCurve = 0x1234

func addCurveTests() {
	for _, curve := range testCurves {
		testCases = append(testCases, testCase{
			name: "CurveTest-Client-" + curve.name,
			config: Config{
				MaxVersion:       VersionTLS12,
				CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				CurvePreferences: []CurveID{curve.id},
			},
			flags:           []string{"-enable-all-curves"},
			expectedCurveID: curve.id,
		})
		testCases = append(testCases, testCase{
			name: "CurveTest-Client-" + curve.name + "-TLS13",
			config: Config{
				MaxVersion:       VersionTLS13,
				CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				CurvePreferences: []CurveID{curve.id},
			},
			flags:           []string{"-enable-all-curves"},
			expectedCurveID: curve.id,
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "CurveTest-Server-" + curve.name,
			config: Config{
				MaxVersion:       VersionTLS12,
				CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				CurvePreferences: []CurveID{curve.id},
			},
			flags:           []string{"-enable-all-curves"},
			expectedCurveID: curve.id,
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "CurveTest-Server-" + curve.name + "-TLS13",
			config: Config{
				MaxVersion:       VersionTLS13,
				CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				CurvePreferences: []CurveID{curve.id},
			},
			flags:           []string{"-enable-all-curves"},
			expectedCurveID: curve.id,
		})
	}

	// The server must be tolerant to bogus curves.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "UnknownCurve",
		config: Config{
			CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CurvePreferences: []CurveID{bogusCurve, CurveP256},
		},
	})

	// The server must not consider ECDHE ciphers when there are no
	// supported curves.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "NoSupportedCurves",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				NoSupportedCurves: true,
			},
		},
		shouldFail:    true,
		expectedError: ":NO_SHARED_CIPHER:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "NoSupportedCurves-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				NoSupportedCurves: true,
			},
		},
		shouldFail:    true,
		expectedError: ":NO_SHARED_CIPHER:",
	})

	// The server must fall back to another cipher when there are no
	// supported curves.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "NoCommonCurves",
		config: Config{
			MaxVersion: VersionTLS12,
			CipherSuites: []uint16{
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			CurvePreferences: []CurveID{CurveP224},
		},
		expectedCipher: TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	})

	// The client must reject bogus curves and disabled curves.
	testCases = append(testCases, testCase{
		name: "BadECDHECurve",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				SendCurve: bogusCurve,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	})
	testCases = append(testCases, testCase{
		name: "BadECDHECurve-TLS13",
		config: Config{
			MaxVersion:   VersionTLS13,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				SendCurve: bogusCurve,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	})

	testCases = append(testCases, testCase{
		name: "UnsupportedCurve",
		config: Config{
			MaxVersion:       VersionTLS12,
			CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CurvePreferences: []CurveID{CurveP256},
			Bugs: ProtocolBugs{
				IgnorePeerCurvePreferences: true,
			},
		},
		flags:         []string{"-p384-only"},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	})

	testCases = append(testCases, testCase{
		// TODO(davidben): Add a TLS 1.3 version where
		// HelloRetryRequest requests an unsupported curve.
		name: "UnsupportedCurve-ServerHello-TLS13",
		config: Config{
			MaxVersion:       VersionTLS12,
			CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CurvePreferences: []CurveID{CurveP384},
			Bugs: ProtocolBugs{
				SendCurve: CurveP256,
			},
		},
		flags:         []string{"-p384-only"},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	})

	// Test invalid curve points.
	testCases = append(testCases, testCase{
		name: "InvalidECDHPoint-Client",
		config: Config{
			MaxVersion:       VersionTLS12,
			CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CurvePreferences: []CurveID{CurveP256},
			Bugs: ProtocolBugs{
				InvalidECDHPoint: true,
			},
		},
		shouldFail:    true,
		expectedError: ":INVALID_ENCODING:",
	})
	testCases = append(testCases, testCase{
		name: "InvalidECDHPoint-Client-TLS13",
		config: Config{
			MaxVersion:       VersionTLS13,
			CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CurvePreferences: []CurveID{CurveP256},
			Bugs: ProtocolBugs{
				InvalidECDHPoint: true,
			},
		},
		shouldFail:    true,
		expectedError: ":INVALID_ENCODING:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "InvalidECDHPoint-Server",
		config: Config{
			MaxVersion:       VersionTLS12,
			CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CurvePreferences: []CurveID{CurveP256},
			Bugs: ProtocolBugs{
				InvalidECDHPoint: true,
			},
		},
		shouldFail:    true,
		expectedError: ":INVALID_ENCODING:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "InvalidECDHPoint-Server-TLS13",
		config: Config{
			MaxVersion:       VersionTLS13,
			CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CurvePreferences: []CurveID{CurveP256},
			Bugs: ProtocolBugs{
				InvalidECDHPoint: true,
			},
		},
		shouldFail:    true,
		expectedError: ":INVALID_ENCODING:",
	})
}

func addCECPQ1Tests() {
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "CECPQ1-Client-BadX25519Part",
		config: Config{
			MaxVersion:   VersionTLS12,
			MinVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384},
			Bugs: ProtocolBugs{
				CECPQ1BadX25519Part: true,
			},
		},
		flags:              []string{"-cipher", "kCECPQ1"},
		shouldFail:         true,
		expectedLocalError: "local error: bad record MAC",
	})
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "CECPQ1-Client-BadNewhopePart",
		config: Config{
			MaxVersion:   VersionTLS12,
			MinVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384},
			Bugs: ProtocolBugs{
				CECPQ1BadNewhopePart: true,
			},
		},
		flags:              []string{"-cipher", "kCECPQ1"},
		shouldFail:         true,
		expectedLocalError: "local error: bad record MAC",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "CECPQ1-Server-BadX25519Part",
		config: Config{
			MaxVersion:   VersionTLS12,
			MinVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384},
			Bugs: ProtocolBugs{
				CECPQ1BadX25519Part: true,
			},
		},
		flags:         []string{"-cipher", "kCECPQ1"},
		shouldFail:    true,
		expectedError: ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "CECPQ1-Server-BadNewhopePart",
		config: Config{
			MaxVersion:   VersionTLS12,
			MinVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384},
			Bugs: ProtocolBugs{
				CECPQ1BadNewhopePart: true,
			},
		},
		flags:         []string{"-cipher", "kCECPQ1"},
		shouldFail:    true,
		expectedError: ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
	})
}

func addKeyExchangeInfoTests() {
	testCases = append(testCases, testCase{
		name: "KeyExchangeInfo-DHE-Client",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				// This is a 1234-bit prime number, generated
				// with:
				// openssl gendh 1234 | openssl asn1parse -i
				DHGroupPrime: bigFromHex("0215C589A86BE450D1255A86D7A08877A70E124C11F0C75E476BA6A2186B1C830D4A132555973F2D5881D5F737BB800B7F417C01EC5960AEBF79478F8E0BBB6A021269BD10590C64C57F50AD8169D5488B56EE38DC5E02DA1A16ED3B5F41FEB2AD184B78A31F3A5B2BEC8441928343DA35DE3D4F89F0D4CEDE0034045084A0D1E6182E5EF7FCA325DD33CE81BE7FA87D43613E8FA7A1457099AB53"),
			},
		},
		flags: []string{"-expect-dhe-group-size", "1234"},
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "KeyExchangeInfo-DHE-Server",
		config: Config{
			MaxVersion:   VersionTLS12,
			CipherSuites: []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		// bssl_shim as a server configures a 2048-bit DHE group.
		flags: []string{"-expect-dhe-group-size", "2048"},
	})

	testCases = append(testCases, testCase{
		name: "KeyExchangeInfo-ECDHE-Client",
		config: Config{
			MaxVersion:       VersionTLS12,
			CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CurvePreferences: []CurveID{CurveX25519},
		},
		flags: []string{"-expect-curve-id", "29", "-enable-all-curves"},
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "KeyExchangeInfo-ECDHE-Server",
		config: Config{
			MaxVersion:       VersionTLS12,
			CipherSuites:     []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CurvePreferences: []CurveID{CurveX25519},
		},
		flags: []string{"-expect-curve-id", "29", "-enable-all-curves"},
	})
}

func addTLS13RecordTests() {
	testCases = append(testCases, testCase{
		name: "TLS13-RecordPadding",
		config: Config{
			MaxVersion: VersionTLS13,
			MinVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				RecordPadding: 10,
			},
		},
	})

	testCases = append(testCases, testCase{
		name: "TLS13-EmptyRecords",
		config: Config{
			MaxVersion: VersionTLS13,
			MinVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				OmitRecordContents: true,
			},
		},
		shouldFail:    true,
		expectedError: ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
	})

	testCases = append(testCases, testCase{
		name: "TLS13-OnlyPadding",
		config: Config{
			MaxVersion: VersionTLS13,
			MinVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				OmitRecordContents: true,
				RecordPadding:      10,
			},
		},
		shouldFail:    true,
		expectedError: ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
	})

	testCases = append(testCases, testCase{
		name: "TLS13-WrongOuterRecord",
		config: Config{
			MaxVersion: VersionTLS13,
			MinVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				OuterRecordType: recordTypeHandshake,
			},
		},
		shouldFail:    true,
		expectedError: ":INVALID_OUTER_RECORD_TYPE:",
	})
}

func addChangeCipherSpecTests() {
	// Test missing ChangeCipherSpecs.
	testCases = append(testCases, testCase{
		name: "SkipChangeCipherSpec-Client",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				SkipChangeCipherSpec: true,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_RECORD:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SkipChangeCipherSpec-Server",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				SkipChangeCipherSpec: true,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_RECORD:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SkipChangeCipherSpec-Server-NPN",
		config: Config{
			MaxVersion: VersionTLS12,
			NextProtos: []string{"bar"},
			Bugs: ProtocolBugs{
				SkipChangeCipherSpec: true,
			},
		},
		flags: []string{
			"-advertise-npn", "\x03foo\x03bar\x03baz",
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_RECORD:",
	})

	// Test synchronization between the handshake and ChangeCipherSpec.
	// Partial post-CCS handshake messages before ChangeCipherSpec should be
	// rejected. Test both with and without handshake packing to handle both
	// when the partial post-CCS message is in its own record and when it is
	// attached to the pre-CCS message.
	for _, packed := range []bool{false, true} {
		var suffix string
		if packed {
			suffix = "-Packed"
		}

		testCases = append(testCases, testCase{
			name: "FragmentAcrossChangeCipherSpec-Client" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					FragmentAcrossChangeCipherSpec: true,
					PackHandshakeFlight:            packed,
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		})
		testCases = append(testCases, testCase{
			name: "FragmentAcrossChangeCipherSpec-Client-Resume" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
			},
			resumeSession: true,
			resumeConfig: &Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					FragmentAcrossChangeCipherSpec: true,
					PackHandshakeFlight:            packed,
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "FragmentAcrossChangeCipherSpec-Server" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					FragmentAcrossChangeCipherSpec: true,
					PackHandshakeFlight:            packed,
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "FragmentAcrossChangeCipherSpec-Server-Resume" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
			},
			resumeSession: true,
			resumeConfig: &Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					FragmentAcrossChangeCipherSpec: true,
					PackHandshakeFlight:            packed,
				},
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		})
		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "FragmentAcrossChangeCipherSpec-Server-NPN" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				NextProtos: []string{"bar"},
				Bugs: ProtocolBugs{
					FragmentAcrossChangeCipherSpec: true,
					PackHandshakeFlight:            packed,
				},
			},
			flags: []string{
				"-advertise-npn", "\x03foo\x03bar\x03baz",
			},
			shouldFail:    true,
			expectedError: ":UNEXPECTED_RECORD:",
		})
	}

	// Test that, in DTLS, ChangeCipherSpec is not allowed when there are
	// messages in the handshake queue. Do this by testing the server
	// reading the client Finished, reversing the flight so Finished comes
	// first.
	testCases = append(testCases, testCase{
		protocol: dtls,
		testType: serverTest,
		name:     "SendUnencryptedFinished-DTLS",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				SendUnencryptedFinished:   true,
				ReverseHandshakeFragments: true,
			},
		},
		shouldFail:    true,
		expectedError: ":BUFFERED_MESSAGES_ON_CIPHER_CHANGE:",
	})

	// Test synchronization between encryption changes and the handshake in
	// TLS 1.3, where ChangeCipherSpec is implicit.
	testCases = append(testCases, testCase{
		name: "PartialEncryptedExtensionsWithServerHello",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				PartialEncryptedExtensionsWithServerHello: true,
			},
		},
		shouldFail:    true,
		expectedError: ":BUFFERED_MESSAGES_ON_CIPHER_CHANGE:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "PartialClientFinishedWithClientHello",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				PartialClientFinishedWithClientHello: true,
			},
		},
		shouldFail:    true,
		expectedError: ":BUFFERED_MESSAGES_ON_CIPHER_CHANGE:",
	})

	// Test that early ChangeCipherSpecs are handled correctly.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "EarlyChangeCipherSpec-server-1",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				EarlyChangeCipherSpec: 1,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_RECORD:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "EarlyChangeCipherSpec-server-2",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				EarlyChangeCipherSpec: 2,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_RECORD:",
	})
	testCases = append(testCases, testCase{
		protocol: dtls,
		name:     "StrayChangeCipherSpec",
		config: Config{
			// TODO(davidben): Once DTLS 1.3 exists, test
			// that stray ChangeCipherSpec messages are
			// rejected.
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				StrayChangeCipherSpec: true,
			},
		},
	})

	// Test that the contents of ChangeCipherSpec are checked.
	testCases = append(testCases, testCase{
		name: "BadChangeCipherSpec-1",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				BadChangeCipherSpec: []byte{2},
			},
		},
		shouldFail:    true,
		expectedError: ":BAD_CHANGE_CIPHER_SPEC:",
	})
	testCases = append(testCases, testCase{
		name: "BadChangeCipherSpec-2",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				BadChangeCipherSpec: []byte{1, 1},
			},
		},
		shouldFail:    true,
		expectedError: ":BAD_CHANGE_CIPHER_SPEC:",
	})
	testCases = append(testCases, testCase{
		protocol: dtls,
		name:     "BadChangeCipherSpec-DTLS-1",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				BadChangeCipherSpec: []byte{2},
			},
		},
		shouldFail:    true,
		expectedError: ":BAD_CHANGE_CIPHER_SPEC:",
	})
	testCases = append(testCases, testCase{
		protocol: dtls,
		name:     "BadChangeCipherSpec-DTLS-2",
		config: Config{
			MaxVersion: VersionTLS12,
			Bugs: ProtocolBugs{
				BadChangeCipherSpec: []byte{1, 1},
			},
		},
		shouldFail:    true,
		expectedError: ":BAD_CHANGE_CIPHER_SPEC:",
	})
}

func addWrongMessageTypeTests() {
	for _, protocol := range []protocol{tls, dtls} {
		var suffix string
		if protocol == dtls {
			suffix = "-DTLS"
		}

		testCases = append(testCases, testCase{
			protocol: protocol,
			testType: serverTest,
			name:     "WrongMessageType-ClientHello" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeClientHello,
				},
			},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		if protocol == dtls {
			testCases = append(testCases, testCase{
				protocol: protocol,
				name:     "WrongMessageType-HelloVerifyRequest" + suffix,
				config: Config{
					MaxVersion: VersionTLS12,
					Bugs: ProtocolBugs{
						SendWrongMessageType: typeHelloVerifyRequest,
					},
				},
				shouldFail:         true,
				expectedError:      ":UNEXPECTED_MESSAGE:",
				expectedLocalError: "remote error: unexpected message",
			})
		}

		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "WrongMessageType-ServerHello" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeServerHello,
				},
			},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "WrongMessageType-ServerCertificate" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeCertificate,
				},
			},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "WrongMessageType-CertificateStatus" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeCertificateStatus,
				},
			},
			flags:              []string{"-enable-ocsp-stapling"},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "WrongMessageType-ServerKeyExchange" + suffix,
			config: Config{
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeServerKeyExchange,
				},
			},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "WrongMessageType-CertificateRequest" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				ClientAuth: RequireAnyClientCert,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeCertificateRequest,
				},
			},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "WrongMessageType-ServerHelloDone" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeServerHelloDone,
				},
			},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		testCases = append(testCases, testCase{
			testType: serverTest,
			protocol: protocol,
			name:     "WrongMessageType-ClientCertificate" + suffix,
			config: Config{
				Certificates: []Certificate{rsaCertificate},
				MaxVersion:   VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeCertificate,
				},
			},
			flags:              []string{"-require-any-client-certificate"},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		testCases = append(testCases, testCase{
			testType: serverTest,
			protocol: protocol,
			name:     "WrongMessageType-CertificateVerify" + suffix,
			config: Config{
				Certificates: []Certificate{rsaCertificate},
				MaxVersion:   VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeCertificateVerify,
				},
			},
			flags:              []string{"-require-any-client-certificate"},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		testCases = append(testCases, testCase{
			testType: serverTest,
			protocol: protocol,
			name:     "WrongMessageType-ClientKeyExchange" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeClientKeyExchange,
				},
			},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		if protocol != dtls {
			testCases = append(testCases, testCase{
				testType: serverTest,
				protocol: protocol,
				name:     "WrongMessageType-NextProtocol" + suffix,
				config: Config{
					MaxVersion: VersionTLS12,
					NextProtos: []string{"bar"},
					Bugs: ProtocolBugs{
						SendWrongMessageType: typeNextProtocol,
					},
				},
				flags:              []string{"-advertise-npn", "\x03foo\x03bar\x03baz"},
				shouldFail:         true,
				expectedError:      ":UNEXPECTED_MESSAGE:",
				expectedLocalError: "remote error: unexpected message",
			})

			testCases = append(testCases, testCase{
				testType: serverTest,
				protocol: protocol,
				name:     "WrongMessageType-ChannelID" + suffix,
				config: Config{
					MaxVersion: VersionTLS12,
					ChannelID:  channelIDKey,
					Bugs: ProtocolBugs{
						SendWrongMessageType: typeChannelID,
					},
				},
				flags: []string{
					"-expect-channel-id",
					base64.StdEncoding.EncodeToString(channelIDBytes),
				},
				shouldFail:         true,
				expectedError:      ":UNEXPECTED_MESSAGE:",
				expectedLocalError: "remote error: unexpected message",
			})
		}

		testCases = append(testCases, testCase{
			testType: serverTest,
			protocol: protocol,
			name:     "WrongMessageType-ClientFinished" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeFinished,
				},
			},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "WrongMessageType-NewSessionTicket" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeNewSessionTicket,
				},
			},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "WrongMessageType-ServerFinished" + suffix,
			config: Config{
				MaxVersion: VersionTLS12,
				Bugs: ProtocolBugs{
					SendWrongMessageType: typeFinished,
				},
			},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

	}
}

func addTLS13WrongMessageTypeTests() {
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "WrongMessageType-TLS13-ClientHello",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SendWrongMessageType: typeClientHello,
			},
		},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
	})

	testCases = append(testCases, testCase{
		name: "WrongMessageType-TLS13-ServerHello",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SendWrongMessageType: typeServerHello,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
		// The alert comes in with the wrong encryption.
		expectedLocalError: "local error: bad record MAC",
	})

	testCases = append(testCases, testCase{
		name: "WrongMessageType-TLS13-EncryptedExtensions",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SendWrongMessageType: typeEncryptedExtensions,
			},
		},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
	})

	testCases = append(testCases, testCase{
		name: "WrongMessageType-TLS13-CertificateRequest",
		config: Config{
			MaxVersion: VersionTLS13,
			ClientAuth: RequireAnyClientCert,
			Bugs: ProtocolBugs{
				SendWrongMessageType: typeCertificateRequest,
			},
		},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
	})

	testCases = append(testCases, testCase{
		name: "WrongMessageType-TLS13-ServerCertificate",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SendWrongMessageType: typeCertificate,
			},
		},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
	})

	testCases = append(testCases, testCase{
		name: "WrongMessageType-TLS13-ServerCertificateVerify",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SendWrongMessageType: typeCertificateVerify,
			},
		},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
	})

	testCases = append(testCases, testCase{
		name: "WrongMessageType-TLS13-ServerFinished",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SendWrongMessageType: typeFinished,
			},
		},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "WrongMessageType-TLS13-ClientCertificate",
		config: Config{
			Certificates: []Certificate{rsaCertificate},
			MaxVersion:   VersionTLS13,
			Bugs: ProtocolBugs{
				SendWrongMessageType: typeCertificate,
			},
		},
		flags:              []string{"-require-any-client-certificate"},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "WrongMessageType-TLS13-ClientCertificateVerify",
		config: Config{
			Certificates: []Certificate{rsaCertificate},
			MaxVersion:   VersionTLS13,
			Bugs: ProtocolBugs{
				SendWrongMessageType: typeCertificateVerify,
			},
		},
		flags:              []string{"-require-any-client-certificate"},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "WrongMessageType-TLS13-ClientFinished",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				SendWrongMessageType: typeFinished,
			},
		},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
	})
}

func addTLS13HandshakeTests() {
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "MissingKeyShare-Client",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				MissingKeyShare: true,
			},
		},
		shouldFail:    true,
		expectedError: ":MISSING_KEY_SHARE:",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "MissingKeyShare-Server",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				MissingKeyShare: true,
			},
		},
		shouldFail:    true,
		expectedError: ":MISSING_KEY_SHARE:",
	})

	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "ClientHelloMissingKeyShare",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				MissingKeyShare: true,
			},
		},
		shouldFail:    true,
		expectedError: ":MISSING_KEY_SHARE:",
	})

	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "MissingKeyShare",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				MissingKeyShare: true,
			},
		},
		shouldFail:    true,
		expectedError: ":MISSING_KEY_SHARE:",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "DuplicateKeyShares",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				DuplicateKeyShares: true,
			},
		},
	})

	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "EmptyEncryptedExtensions",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				EmptyEncryptedExtensions: true,
			},
		},
		shouldFail:         true,
		expectedLocalError: "remote error: error decoding message",
	})

	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "EncryptedExtensionsWithKeyShare",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				EncryptedExtensionsWithKeyShare: true,
			},
		},
		shouldFail:         true,
		expectedLocalError: "remote error: unsupported extension",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SendHelloRetryRequest",
		config: Config{
			MaxVersion: VersionTLS13,
			// Require a HelloRetryRequest for every curve.
			DefaultCurves: []CurveID{},
		},
		expectedCurveID: CurveX25519,
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SendHelloRetryRequest-2",
		config: Config{
			MaxVersion:    VersionTLS13,
			DefaultCurves: []CurveID{CurveP384},
		},
		// Although the ClientHello did not predict our preferred curve,
		// we always select it whether it is predicted or not.
		expectedCurveID: CurveX25519,
	})

	testCases = append(testCases, testCase{
		name: "UnknownCurve-HelloRetryRequest",
		config: Config{
			MaxVersion: VersionTLS13,
			// P-384 requires HelloRetryRequest in BoringSSL.
			CurvePreferences: []CurveID{CurveP384},
			Bugs: ProtocolBugs{
				SendHelloRetryRequestCurve: bogusCurve,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	})

	testCases = append(testCases, testCase{
		name: "DisabledCurve-HelloRetryRequest",
		config: Config{
			MaxVersion:       VersionTLS13,
			CurvePreferences: []CurveID{CurveP256},
			Bugs: ProtocolBugs{
				IgnorePeerCurvePreferences: true,
			},
		},
		flags:         []string{"-p384-only"},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	})

	testCases = append(testCases, testCase{
		name: "UnnecessaryHelloRetryRequest",
		config: Config{
			MaxVersion: VersionTLS13,
			Bugs: ProtocolBugs{
				UnnecessaryHelloRetryRequest: true,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	})

	testCases = append(testCases, testCase{
		name: "SecondHelloRetryRequest",
		config: Config{
			MaxVersion: VersionTLS13,
			// P-384 requires HelloRetryRequest in BoringSSL.
			CurvePreferences: []CurveID{CurveP384},
			Bugs: ProtocolBugs{
				SecondHelloRetryRequest: true,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SecondClientHelloMissingKeyShare",
		config: Config{
			MaxVersion:    VersionTLS13,
			DefaultCurves: []CurveID{},
			Bugs: ProtocolBugs{
				SecondClientHelloMissingKeyShare: true,
			},
		},
		shouldFail:    true,
		expectedError: ":MISSING_KEY_SHARE:",
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SecondClientHelloWrongCurve",
		config: Config{
			MaxVersion:    VersionTLS13,
			DefaultCurves: []CurveID{},
			Bugs: ProtocolBugs{
				MisinterpretHelloRetryRequestCurve: CurveP521,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	})

	testCases = append(testCases, testCase{
		name: "HelloRetryRequestVersionMismatch",
		config: Config{
			MaxVersion: VersionTLS13,
			// P-384 requires HelloRetryRequest in BoringSSL.
			CurvePreferences: []CurveID{CurveP384},
			Bugs: ProtocolBugs{
				SendServerHelloVersion: 0x0305,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_VERSION_NUMBER:",
	})

	testCases = append(testCases, testCase{
		name: "HelloRetryRequestCurveMismatch",
		config: Config{
			MaxVersion: VersionTLS13,
			// P-384 requires HelloRetryRequest in BoringSSL.
			CurvePreferences: []CurveID{CurveP384},
			Bugs: ProtocolBugs{
				// Send P-384 (correct) in the HelloRetryRequest.
				SendHelloRetryRequestCurve: CurveP384,
				// But send P-256 in the ServerHello.
				SendCurve: CurveP256,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	})

	// Test the server selecting a curve that requires a HelloRetryRequest
	// without sending it.
	testCases = append(testCases, testCase{
		name: "SkipHelloRetryRequest",
		config: Config{
			MaxVersion: VersionTLS13,
			// P-384 requires HelloRetryRequest in BoringSSL.
			CurvePreferences: []CurveID{CurveP384},
			Bugs: ProtocolBugs{
				SkipHelloRetryRequest: true,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_CURVE:",
	})
}

func worker(statusChan chan statusMsg, c chan *testCase, shimPath string, wg *sync.WaitGroup) {
	defer wg.Done()

	for test := range c {
		var err error

		if *mallocTest < 0 {
			statusChan <- statusMsg{test: test, started: true}
			err = runTest(test, shimPath, -1)
		} else {
			for mallocNumToFail := int64(*mallocTest); ; mallocNumToFail++ {
				statusChan <- statusMsg{test: test, started: true}
				if err = runTest(test, shimPath, mallocNumToFail); err != errMoreMallocs {
					if err != nil {
						fmt.Printf("\n\nmalloc test failed at %d: %s\n", mallocNumToFail, err)
					}
					break
				}
			}
		}
		statusChan <- statusMsg{test: test, err: err}
	}
}

type statusMsg struct {
	test    *testCase
	started bool
	err     error
}

func statusPrinter(doneChan chan *testOutput, statusChan chan statusMsg, total int) {
	var started, done, failed, lineLen int

	testOutput := newTestOutput()
	for msg := range statusChan {
		if !*pipe {
			// Erase the previous status line.
			var erase string
			for i := 0; i < lineLen; i++ {
				erase += "\b \b"
			}
			fmt.Print(erase)
		}

		if msg.started {
			started++
		} else {
			done++

			if msg.err != nil {
				fmt.Printf("FAILED (%s)\n%s\n", msg.test.name, msg.err)
				failed++
				testOutput.addResult(msg.test.name, "FAIL")
			} else {
				if *pipe {
					// Print each test instead of a status line.
					fmt.Printf("PASSED (%s)\n", msg.test.name)
				}
				testOutput.addResult(msg.test.name, "PASS")
			}
		}

		if !*pipe {
			// Print a new status line.
			line := fmt.Sprintf("%d/%d/%d/%d", failed, done, started, total)
			lineLen = len(line)
			os.Stdout.WriteString(line)
		}
	}

	doneChan <- testOutput
}

func main() {
	flag.Parse()
	*resourceDir = path.Clean(*resourceDir)
	initCertificates()

	addBasicTests()
	addCipherSuiteTests()
	addBadECDSASignatureTests()
	addCBCPaddingTests()
	addCBCSplittingTests()
	addClientAuthTests()
	addDDoSCallbackTests()
	addVersionNegotiationTests()
	addMinimumVersionTests()
	addExtensionTests()
	addResumptionVersionTests()
	addExtendedMasterSecretTests()
	addRenegotiationTests()
	addDTLSReplayTests()
	addSignatureAlgorithmTests()
	addDTLSRetransmitTests()
	addExportKeyingMaterialTests()
	addTLSUniqueTests()
	addCustomExtensionTests()
	addRSAClientKeyExchangeTests()
	addCurveTests()
	addCECPQ1Tests()
	addKeyExchangeInfoTests()
	addTLS13RecordTests()
	addAllStateMachineCoverageTests()
	addChangeCipherSpecTests()
	addWrongMessageTypeTests()
	addTLS13WrongMessageTypeTests()
	addTLS13HandshakeTests()

	var wg sync.WaitGroup

	statusChan := make(chan statusMsg, *numWorkers)
	testChan := make(chan *testCase, *numWorkers)
	doneChan := make(chan *testOutput)

	go statusPrinter(doneChan, statusChan, len(testCases))

	for i := 0; i < *numWorkers; i++ {
		wg.Add(1)
		go worker(statusChan, testChan, *shimPath, &wg)
	}

	var foundTest bool
	for i := range testCases {
		if len(*testToRun) == 0 || *testToRun == testCases[i].name {
			foundTest = true
			testChan <- &testCases[i]
		}
	}
	if !foundTest {
		fmt.Fprintf(os.Stderr, "No test named '%s'\n", *testToRun)
		os.Exit(1)
	}

	close(testChan)
	wg.Wait()
	close(statusChan)
	testOutput := <-doneChan

	fmt.Printf("\n")

	if *jsonOutput != "" {
		if err := testOutput.writeTo(*jsonOutput); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
	}

	if !testOutput.allPassed {
		os.Exit(1)
	}
}
