package main

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
	flagDebug       = flag.Bool("debug", false, "Hexdump the contents of the connection")
	mallocTest      = flag.Int64("malloc-test", -1, "If non-negative, run each test with each malloc in turn failing from the given number onwards.")
	mallocTestDebug = flag.Bool("malloc-test-debug", false, "If true, ask bssl_shim to abort rather than fail a malloc. This can be used with a specific value for --malloc-test to identity the malloc failing that is causing problems.")
	jsonOutput      = flag.String("json-output", "", "The file to output JSON results to.")
	pipe            = flag.Bool("pipe", false, "If true, print status output suitable for piping into another program.")
)

const (
	rsaCertificateFile   = "cert.pem"
	ecdsaCertificateFile = "ecdsa_cert.pem"
)

const (
	rsaKeyFile       = "key.pem"
	ecdsaKeyFile     = "ecdsa_key.pem"
	channelIDKeyFile = "channel_id_key.pem"
)

var rsaCertificate, ecdsaCertificate Certificate
var channelIDKey *ecdsa.PrivateKey
var channelIDBytes []byte

var testOCSPResponse = []byte{1, 2, 3, 4}
var testSCTList = []byte{5, 6, 7, 8}

func initCertificates() {
	var err error
	rsaCertificate, err = LoadX509KeyPair(rsaCertificateFile, rsaKeyFile)
	if err != nil {
		panic(err)
	}
	rsaCertificate.OCSPStaple = testOCSPResponse
	rsaCertificate.SignedCertificateTimestampList = testSCTList

	ecdsaCertificate, err = LoadX509KeyPair(ecdsaCertificateFile, ecdsaKeyFile)
	if err != nil {
		panic(err)
	}
	ecdsaCertificate.OCSPStaple = testOCSPResponse
	ecdsaCertificate.SignedCertificateTimestampList = testSCTList

	channelIDPEMBlock, err := ioutil.ReadFile(channelIDKeyFile)
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
	// expectChannelID controls whether the connection should have
	// negotiated a Channel ID with channelIDKey.
	expectChannelID bool
	// expectedNextProto controls whether the connection should
	// negotiate a next protocol via NPN or ALPN.
	expectedNextProto string
	// expectedNextProtoType, if non-zero, is the expected next
	// protocol negotiation mechanism.
	expectedNextProtoType int
	// expectedSRTPProtectionProfile is the DTLS-SRTP profile that
	// should be negotiated. If zero, none should be negotiated.
	expectedSRTPProtectionProfile uint16
	// messageLen is the length, in bytes, of the test message that will be
	// sent.
	messageLen int
	// certFile is the path to the certificate to use for the server.
	certFile string
	// keyFile is the path to the private key to use for the server.
	keyFile string
	// resumeSession controls whether a second connection should be tested
	// which attempts to resume the first session.
	resumeSession bool
	// resumeConfig, if not nil, points to a Config to be used on
	// resumption. Unless newSessionsOnResume is set,
	// SessionTicketKey, ServerSessionCache, and
	// ClientSessionCache are copied from the initial connection's
	// config. If nil, the initial connection's config is used.
	resumeConfig *Config
	// newSessionsOnResume, if true, will cause resumeConfig to
	// use a different session resumption context.
	newSessionsOnResume bool
	// sendPrefix sends a prefix on the socket before actually performing a
	// handshake.
	sendPrefix string
	// shimWritesFirst controls whether the shim sends an initial "hello"
	// message before doing a roundtrip with the runner.
	shimWritesFirst bool
	// renegotiate indicates the the connection should be renegotiated
	// during the exchange.
	renegotiate bool
	// renegotiateCiphers is a list of ciphersuite ids that will be
	// switched in just before renegotiation.
	renegotiateCiphers []uint16
	// replayWrites, if true, configures the underlying transport
	// to replay every write it makes in DTLS tests.
	replayWrites bool
	// damageFirstWrite, if true, configures the underlying transport to
	// damage the final byte of the first application data write.
	damageFirstWrite bool
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
		name:     "FragmentedClientVersion",
		config: Config{
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: 1,
				FragmentClientVersion:    true,
			},
		},
		expectedVersion: VersionTLS12,
	},
	{
		testType: serverTest,
		name:     "MinorVersionTolerance",
		config: Config{
			Bugs: ProtocolBugs{
				SendClientVersion: 0x03ff,
			},
		},
		expectedVersion: VersionTLS12,
	},
	{
		testType: serverTest,
		name:     "MajorVersionTolerance",
		config: Config{
			Bugs: ProtocolBugs{
				SendClientVersion: 0x0400,
			},
		},
		expectedVersion: VersionTLS12,
	},
	{
		testType: serverTest,
		name:     "VersionTooLow",
		config: Config{
			Bugs: ProtocolBugs{
				SendClientVersion: 0x0200,
			},
		},
		shouldFail:    true,
		expectedError: ":UNSUPPORTED_PROTOCOL:",
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
		expectedError: ":UNKNOWN_PROTOCOL:",
	},
	{
		name: "SkipCipherVersionCheck",
		config: Config{
			CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			MaxVersion:   VersionTLS11,
			Bugs: ProtocolBugs{
				SkipCipherVersionCheck: true,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_CIPHER_RETURNED:",
	},
	{
		name: "RSAEphemeralKey",
		config: Config{
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
		flags:         []string{"-no-tls12", "-no-tls11", "-no-tls1", "-no-ssl3"},
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
		name: "NoSharedCipher",
		config: Config{
			CipherSuites: []uint16{},
		},
		shouldFail:    true,
		expectedError: ":HANDSHAKE_FAILURE_ON_CLIENT_HELLO:",
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
			CipherSuites: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			Certificates: []Certificate{getECDSACertificate()},
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
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			Certificates: []Certificate{getRSACertificate()},
			Bugs: ProtocolBugs{
				SendCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
		},
		shouldFail:    true,
		expectedError: ":WRONG_CERTIFICATE_TYPE:",
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
		name: "AppDataAfterChangeCipherSpec",
		config: Config{
			Bugs: ProtocolBugs{
				AppDataAfterChangeCipherSpec: []byte("TEST MESSAGE"),
			},
		},
		shouldFail:    true,
		expectedError: ":DATA_BETWEEN_CCS_AND_FINISHED:",
	},
	{
		protocol: dtls,
		name:     "AppDataAfterChangeCipherSpec-DTLS",
		config: Config{
			Bugs: ProtocolBugs{
				AppDataAfterChangeCipherSpec: []byte("TEST MESSAGE"),
			},
		},
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
			"-advertise-alpn", "\x03foo",
		},
		shimWritesFirst: true,
		shouldFail:      true,
		expectedError:   ":UNEXPECTED_RECORD:",
	},
	{
		name: "FalseStart-SkipServerSecondLeg-Implicit",
		config: Config{
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
		name: "WrongMessageType",
		config: Config{
			Bugs: ProtocolBugs{
				WrongCertificateMessageType: true,
			},
		},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
	},
	{
		protocol: dtls,
		name:     "WrongMessageType-DTLS",
		config: Config{
			Bugs: ProtocolBugs{
				WrongCertificateMessageType: true,
			},
		},
		shouldFail:         true,
		expectedError:      ":UNEXPECTED_MESSAGE:",
		expectedLocalError: "remote error: unexpected message",
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
		name:     "SplitFragmentHeader-DTLS",
		config: Config{
			Bugs: ProtocolBugs{
				SplitFragmentHeader: true,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
	},
	{
		protocol: dtls,
		name:     "SplitFragmentBody-DTLS",
		config: Config{
			Bugs: ProtocolBugs{
				SplitFragmentBody: true,
			},
		},
		shouldFail:    true,
		expectedError: ":UNEXPECTED_MESSAGE:",
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
}

func doExchange(test *testCase, config *Config, conn net.Conn, messageLen int, isResume bool) error {
	var connDebug *recordingConn
	var connDamage *damageAdaptor
	if *flagDebug {
		connDebug = &recordingConn{Conn: conn}
		conn = connDebug
		defer func() {
			connDebug.WriteTo(os.Stdout)
		}()
	}

	if test.protocol == dtls {
		config.Bugs.PacketAdaptor = newPacketAdaptor(conn)
		conn = config.Bugs.PacketAdaptor
		if test.replayWrites {
			conn = newReplayAdaptor(conn)
		}
	}

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
	if vers := tlsConn.ConnectionState().Version; expectedVersion != 0 && vers != expectedVersion {
		return fmt.Errorf("got version %x, expected %x", vers, expectedVersion)
	}

	if test.expectChannelID {
		channelID := tlsConn.ConnectionState().ChannelID
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
		if actual := tlsConn.ConnectionState().NegotiatedProtocol; actual != expected {
			return fmt.Errorf("next proto mismatch: got %s, wanted %s", actual, expected)
		}
	}

	if test.expectedNextProtoType != 0 {
		if (test.expectedNextProtoType == alpn) != tlsConn.ConnectionState().NegotiatedProtocolFromALPN {
			return fmt.Errorf("next proto type mismatch")
		}
	}

	if p := tlsConn.ConnectionState().SRTPProtectionProfile; p != test.expectedSRTPProtectionProfile {
		return fmt.Errorf("SRTP profile mismatch: got %d, wanted %d", p, test.expectedSRTPProtectionProfile)
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

	if test.renegotiate {
		if test.renegotiateCiphers != nil {
			config.CipherSuites = test.renegotiateCiphers
		}
		if err := tlsConn.Renegotiate(); err != nil {
			return err
		}
	} else if test.renegotiateCiphers != nil {
		panic("renegotiateCiphers without renegotiate")
	}

	if test.damageFirstWrite {
		connDamage.setDamage(true)
		tlsConn.Write([]byte("DAMAGED WRITE"))
		connDamage.setDamage(false)
	}

	if messageLen < 0 {
		if test.protocol == dtls {
			return fmt.Errorf("messageLen < 0 not supported for DTLS tests")
		}
		// Read until EOF.
		_, err := io.Copy(ioutil.Discard, tlsConn)
		return err
	}

	var testMessage []byte
	if config.Bugs.AppDataAfterChangeCipherSpec != nil {
		// We've already sent a message. Expect the shim to echo it
		// back.
		testMessage = config.Bugs.AppDataAfterChangeCipherSpec
	} else {
		if messageLen == 0 {
			messageLen = 32
		}
		testMessage = make([]byte, messageLen)
		for i := range testMessage {
			testMessage[i] = 0x42
		}
		tlsConn.Write(testMessage)
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

func runTest(test *testCase, buildDir string, mallocNumToFail int64) error {
	if !test.shouldFail && (len(test.expectedError) > 0 || len(test.expectedLocalError) > 0) {
		panic("Error expected without shouldFail in " + test.name)
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

	shim_path := path.Join(buildDir, "ssl/test/bssl_shim")
	flags := []string{"-port", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)}
	if test.testType == serverTest {
		flags = append(flags, "-server")

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

	if test.protocol == dtls {
		flags = append(flags, "-dtls")
	}

	if test.resumeSession {
		flags = append(flags, "-resume")
	}

	if test.shimWritesFirst {
		flags = append(flags, "-shim-writes-first")
	}

	flags = append(flags, test.flags...)

	var shim *exec.Cmd
	if *useValgrind {
		shim = valgrindOf(false, shim_path, flags...)
	} else if *useGDB {
		shim = gdbOf(shim_path, flags...)
	} else {
		shim = exec.Command(shim_path, flags...)
	}
	shim.Stdin = os.Stdin
	var stdoutBuf, stderrBuf bytes.Buffer
	shim.Stdout = &stdoutBuf
	shim.Stderr = &stderrBuf
	if mallocNumToFail >= 0 {
		shim.Env = os.Environ()
		shim.Env = append(shim.Env, "MALLOC_NUMBER_TO_FAIL="+strconv.FormatInt(mallocNumToFail, 10))
		if *mallocTestDebug {
			shim.Env = append(shim.Env, "MALLOC_ABORT_ON_FAIL=1")
		}
		shim.Env = append(shim.Env, "_MALLOC_CHECK=1")
	}

	if err := shim.Start(); err != nil {
		panic(err)
	}
	waitChan := make(chan error, 1)
	go func() { waitChan <- shim.Wait() }()

	config := test.config
	config.ClientSessionCache = NewLRUClientSessionCache(1)
	config.ServerSessionCache = NewLRUServerSessionCache(1)
	if test.testType == clientTest {
		if len(config.Certificates) == 0 {
			config.Certificates = []Certificate{getRSACertificate()}
		}
	} else {
		// Supply a ServerName to ensure a constant session cache key,
		// rather than falling back to net.Conn.RemoteAddr.
		if len(config.ServerName) == 0 {
			config.ServerName = "test"
		}
	}

	conn, err := acceptOrWait(listener, waitChan)
	if err == nil {
		err = doExchange(test, &config, conn, test.messageLen, false /* not a resumption */)
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
				resumeConfig.Certificates = []Certificate{getRSACertificate()}
			}
			if !test.newSessionsOnResume {
				resumeConfig.SessionTicketKey = config.SessionTicketKey
				resumeConfig.ClientSessionCache = config.ClientSessionCache
				resumeConfig.ServerSessionCache = config.ServerSessionCache
			}
		} else {
			resumeConfig = config
		}
		var connResume net.Conn
		connResume, err = acceptOrWait(listener, waitChan)
		if err == nil {
			err = doExchange(test, &resumeConfig, connResume, test.messageLen, true /* resumption */)
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
	hasDTLS bool
}{
	{"SSL3", VersionSSL30, "-no-ssl3", false},
	{"TLS1", VersionTLS10, "-no-tls1", true},
	{"TLS11", VersionTLS11, "-no-tls11", false},
	{"TLS12", VersionTLS12, "-no-tls12", true},
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
	{"ECDHE-ECDSA-RC4-SHA", TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
	{"ECDHE-PSK-WITH-AES-128-GCM-SHA256", TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256},
	{"ECDHE-RSA-AES128-GCM", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	{"ECDHE-RSA-AES128-SHA", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
	{"ECDHE-RSA-AES128-SHA256", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256},
	{"ECDHE-RSA-AES256-GCM", TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	{"ECDHE-RSA-AES256-SHA", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
	{"ECDHE-RSA-AES256-SHA384", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384},
	{"ECDHE-RSA-RC4-SHA", TLS_ECDHE_RSA_WITH_RC4_128_SHA},
	{"PSK-AES128-CBC-SHA", TLS_PSK_WITH_AES_128_CBC_SHA},
	{"PSK-AES256-CBC-SHA", TLS_PSK_WITH_AES_256_CBC_SHA},
	{"PSK-RC4-SHA", TLS_PSK_WITH_RC4_128_SHA},
	{"RC4-MD5", TLS_RSA_WITH_RC4_128_MD5},
	{"RC4-SHA", TLS_RSA_WITH_RC4_128_SHA},
}

func hasComponent(suiteName, component string) bool {
	return strings.Contains("-"+suiteName+"-", "-"+component+"-")
}

func isTLS12Only(suiteName string) bool {
	return hasComponent(suiteName, "GCM") ||
		hasComponent(suiteName, "SHA256") ||
		hasComponent(suiteName, "SHA384")
}

func isDTLSCipher(suiteName string) bool {
	return !hasComponent(suiteName, "RC4")
}

func addCipherSuiteTests() {
	for _, suite := range testCipherSuites {
		const psk = "12345"
		const pskIdentity = "luggage combo"

		var cert Certificate
		var certFile string
		var keyFile string
		if hasComponent(suite.name, "ECDSA") {
			cert = getECDSACertificate()
			certFile = ecdsaCertificateFile
			keyFile = ecdsaKeyFile
		} else {
			cert = getRSACertificate()
			certFile = rsaCertificateFile
			keyFile = rsaKeyFile
		}

		var flags []string
		if hasComponent(suite.name, "PSK") {
			flags = append(flags,
				"-psk", psk,
				"-psk-identity", pskIdentity)
		}

		for _, ver := range tlsVersions {
			if ver.version < VersionTLS12 && isTLS12Only(suite.name) {
				continue
			}

			testCases = append(testCases, testCase{
				testType: clientTest,
				name:     ver.name + "-" + suite.name + "-client",
				config: Config{
					MinVersion:           ver.version,
					MaxVersion:           ver.version,
					CipherSuites:         []uint16{suite.id},
					Certificates:         []Certificate{cert},
					PreSharedKey:         []byte(psk),
					PreSharedKeyIdentity: pskIdentity,
				},
				flags:         flags,
				resumeSession: true,
			})

			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     ver.name + "-" + suite.name + "-server",
				config: Config{
					MinVersion:           ver.version,
					MaxVersion:           ver.version,
					CipherSuites:         []uint16{suite.id},
					Certificates:         []Certificate{cert},
					PreSharedKey:         []byte(psk),
					PreSharedKeyIdentity: pskIdentity,
				},
				certFile:      certFile,
				keyFile:       keyFile,
				flags:         flags,
				resumeSession: true,
			})

			if ver.hasDTLS && isDTLSCipher(suite.name) {
				testCases = append(testCases, testCase{
					testType: clientTest,
					protocol: dtls,
					name:     "D" + ver.name + "-" + suite.name + "-client",
					config: Config{
						MinVersion:           ver.version,
						MaxVersion:           ver.version,
						CipherSuites:         []uint16{suite.id},
						Certificates:         []Certificate{cert},
						PreSharedKey:         []byte(psk),
						PreSharedKeyIdentity: pskIdentity,
					},
					flags:         flags,
					resumeSession: true,
				})
				testCases = append(testCases, testCase{
					testType: serverTest,
					protocol: dtls,
					name:     "D" + ver.name + "-" + suite.name + "-server",
					config: Config{
						MinVersion:           ver.version,
						MaxVersion:           ver.version,
						CipherSuites:         []uint16{suite.id},
						Certificates:         []Certificate{cert},
						PreSharedKey:         []byte(psk),
						PreSharedKeyIdentity: pskIdentity,
					},
					certFile:      certFile,
					keyFile:       keyFile,
					flags:         flags,
					resumeSession: true,
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
				"-cert-file", rsaCertificateFile,
				"-key-file", rsaKeyFile,
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
					Certificates: []Certificate{ecdsaCertificate},
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
					"-cert-file", ecdsaCertificateFile,
					"-key-file", ecdsaKeyFile,
				},
			})
		}
	}
}

func addExtendedMasterSecretTests() {
	const expectEMSFlag = "-expect-extended-master-secret"

	for _, with := range []bool{false, true} {
		prefix := "No"
		var flags []string
		if with {
			prefix = ""
			flags = []string{expectEMSFlag}
		}

		for _, isClient := range []bool{false, true} {
			suffix := "-Server"
			testType := serverTest
			if isClient {
				suffix = "-Client"
				testType = clientTest
			}

			for _, ver := range tlsVersions {
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

	// When a session is resumed, it should still be aware that its master
	// secret was generated via EMS and thus it's safe to use tls-unique.
	testCases = append(testCases, testCase{
		name: "ExtendedMasterSecret-Resume",
		config: Config{
			Bugs: ProtocolBugs{
				RequireExtendedMasterSecret: true,
			},
		},
		flags:         []string{expectEMSFlag},
		resumeSession: true,
	})
}

// Adds tests that try to cover the range of the handshake state machine, under
// various conditions. Some of these are redundant with other tests, but they
// only cover the synchronous case.
func addStateMachineCoverageTests(async, splitHandshake bool, protocol protocol) {
	var suffix string
	var flags []string
	var maxHandshakeRecordLength int
	if protocol == dtls {
		suffix = "-DTLS"
	}
	if async {
		suffix += "-Async"
		flags = append(flags, "-async")
	} else {
		suffix += "-Sync"
	}
	if splitHandshake {
		suffix += "-SplitHandshakeRecords"
		maxHandshakeRecordLength = 1
	}

	// Basic handshake, with resumption. Client and server,
	// session ID and session ticket.
	testCases = append(testCases, testCase{
		protocol: protocol,
		name:     "Basic-Client" + suffix,
		config: Config{
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags:         flags,
		resumeSession: true,
	})
	testCases = append(testCases, testCase{
		protocol: protocol,
		name:     "Basic-Client-RenewTicket" + suffix,
		config: Config{
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
				RenewTicketOnResume:      true,
			},
		},
		flags:         flags,
		resumeSession: true,
	})
	testCases = append(testCases, testCase{
		protocol: protocol,
		name:     "Basic-Client-NoTicket" + suffix,
		config: Config{
			SessionTicketsDisabled: true,
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags:         flags,
		resumeSession: true,
	})
	testCases = append(testCases, testCase{
		protocol: protocol,
		name:     "Basic-Client-Implicit" + suffix,
		config: Config{
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags:         append(flags, "-implicit-handshake"),
		resumeSession: true,
	})
	testCases = append(testCases, testCase{
		protocol: protocol,
		testType: serverTest,
		name:     "Basic-Server" + suffix,
		config: Config{
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags:         flags,
		resumeSession: true,
	})
	testCases = append(testCases, testCase{
		protocol: protocol,
		testType: serverTest,
		name:     "Basic-Server-NoTickets" + suffix,
		config: Config{
			SessionTicketsDisabled: true,
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags:         flags,
		resumeSession: true,
	})
	testCases = append(testCases, testCase{
		protocol: protocol,
		testType: serverTest,
		name:     "Basic-Server-Implicit" + suffix,
		config: Config{
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags:         append(flags, "-implicit-handshake"),
		resumeSession: true,
	})
	testCases = append(testCases, testCase{
		protocol: protocol,
		testType: serverTest,
		name:     "Basic-Server-EarlyCallback" + suffix,
		config: Config{
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags:         append(flags, "-use-early-callback"),
		resumeSession: true,
	})

	// TLS client auth.
	testCases = append(testCases, testCase{
		protocol: protocol,
		testType: clientTest,
		name:     "ClientAuth-Client" + suffix,
		config: Config{
			ClientAuth: RequireAnyClientCert,
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: append(flags,
			"-cert-file", rsaCertificateFile,
			"-key-file", rsaKeyFile),
	})
	testCases = append(testCases, testCase{
		protocol: protocol,
		testType: serverTest,
		name:     "ClientAuth-Server" + suffix,
		config: Config{
			Certificates: []Certificate{rsaCertificate},
		},
		flags: append(flags, "-require-any-client-certificate"),
	})

	// No session ticket support; server doesn't send NewSessionTicket.
	testCases = append(testCases, testCase{
		protocol: protocol,
		name:     "SessionTicketsDisabled-Client" + suffix,
		config: Config{
			SessionTicketsDisabled: true,
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: flags,
	})
	testCases = append(testCases, testCase{
		protocol: protocol,
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

	// Skip ServerKeyExchange in PSK key exchange if there's no
	// identity hint.
	testCases = append(testCases, testCase{
		protocol: protocol,
		name:     "EmptyPSKHint-Client" + suffix,
		config: Config{
			CipherSuites: []uint16{TLS_PSK_WITH_AES_128_CBC_SHA},
			PreSharedKey: []byte("secret"),
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: append(flags, "-psk", "secret"),
	})
	testCases = append(testCases, testCase{
		protocol: protocol,
		testType: serverTest,
		name:     "EmptyPSKHint-Server" + suffix,
		config: Config{
			CipherSuites: []uint16{TLS_PSK_WITH_AES_128_CBC_SHA},
			PreSharedKey: []byte("secret"),
			Bugs: ProtocolBugs{
				MaxHandshakeRecordLength: maxHandshakeRecordLength,
			},
		},
		flags: append(flags, "-psk", "secret"),
	})

	if protocol == tls {
		// NPN on client and server; results in post-handshake message.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "NPN-Client" + suffix,
			config: Config{
				NextProtos: []string{"foo"},
				Bugs: ProtocolBugs{
					MaxHandshakeRecordLength: maxHandshakeRecordLength,
				},
			},
			flags:                 append(flags, "-select-next-proto", "foo"),
			expectedNextProto:     "foo",
			expectedNextProtoType: npn,
		})
		testCases = append(testCases, testCase{
			protocol: protocol,
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
			expectedNextProto:     "bar",
			expectedNextProtoType: npn,
		})

		// TODO(davidben): Add tests for when False Start doesn't trigger.

		// Client does False Start and negotiates NPN.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "FalseStart" + suffix,
			config: Config{
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					ExpectFalseStart:         true,
					MaxHandshakeRecordLength: maxHandshakeRecordLength,
				},
			},
			flags: append(flags,
				"-false-start",
				"-select-next-proto", "foo"),
			shimWritesFirst: true,
			resumeSession:   true,
		})

		// Client does False Start and negotiates ALPN.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "FalseStart-ALPN" + suffix,
			config: Config{
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					ExpectFalseStart:         true,
					MaxHandshakeRecordLength: maxHandshakeRecordLength,
				},
			},
			flags: append(flags,
				"-false-start",
				"-advertise-alpn", "\x03foo"),
			shimWritesFirst: true,
			resumeSession:   true,
		})

		// Client does False Start but doesn't explicitly call
		// SSL_connect.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "FalseStart-Implicit" + suffix,
			config: Config{
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:   []string{"foo"},
				Bugs: ProtocolBugs{
					MaxHandshakeRecordLength: maxHandshakeRecordLength,
				},
			},
			flags: append(flags,
				"-implicit-handshake",
				"-false-start",
				"-advertise-alpn", "\x03foo"),
		})

		// False Start without session tickets.
		testCases = append(testCases, testCase{
			name: "FalseStart-SessionTicketsDisabled" + suffix,
			config: Config{
				CipherSuites:           []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				NextProtos:             []string{"foo"},
				SessionTicketsDisabled: true,
				Bugs: ProtocolBugs{
					ExpectFalseStart:         true,
					MaxHandshakeRecordLength: maxHandshakeRecordLength,
				},
			},
			flags: append(flags,
				"-false-start",
				"-select-next-proto", "foo",
			),
			shimWritesFirst: true,
		})

		// Server parses a V2ClientHello.
		testCases = append(testCases, testCase{
			protocol: protocol,
			testType: serverTest,
			name:     "SendV2ClientHello" + suffix,
			config: Config{
				// Choose a cipher suite that does not involve
				// elliptic curves, so no extensions are
				// involved.
				CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA},
				Bugs: ProtocolBugs{
					MaxHandshakeRecordLength: maxHandshakeRecordLength,
					SendV2ClientHello:        true,
				},
			},
			flags: flags,
		})

		// Client sends a Channel ID.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "ChannelID-Client" + suffix,
			config: Config{
				RequestChannelID: true,
				Bugs: ProtocolBugs{
					MaxHandshakeRecordLength: maxHandshakeRecordLength,
				},
			},
			flags: append(flags,
				"-send-channel-id", channelIDKeyFile,
			),
			resumeSession:   true,
			expectChannelID: true,
		})

		// Server accepts a Channel ID.
		testCases = append(testCases, testCase{
			protocol: protocol,
			testType: serverTest,
			name:     "ChannelID-Server" + suffix,
			config: Config{
				ChannelID: channelIDKey,
				Bugs: ProtocolBugs{
					MaxHandshakeRecordLength: maxHandshakeRecordLength,
				},
			},
			flags: append(flags,
				"-expect-channel-id",
				base64.StdEncoding.EncodeToString(channelIDBytes),
			),
			resumeSession:   true,
			expectChannelID: true,
		})
	} else {
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     "SkipHelloVerifyRequest" + suffix,
			config: Config{
				Bugs: ProtocolBugs{
					MaxHandshakeRecordLength: maxHandshakeRecordLength,
					SkipHelloVerifyRequest:   true,
				},
			},
			flags: flags,
		})
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
							ExpectInitialRecordVersion: expectedVersion,
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
							ExpectInitialRecordVersion: expectedVersion,
						},
					},
					flags:           []string{"-max-version", shimVersFlag},
					expectedVersion: expectedVersion,
				})
			}
		}
	}
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
				var expectedError string
				var expectedLocalError string
				if runnerVers.version >= shimVers.version {
					expectedVersion = runnerVers.version
				} else {
					shouldFail = true
					expectedError = ":UNSUPPORTED_PROTOCOL:"
					if runnerVers.version > VersionSSL30 {
						expectedLocalError = "remote error: protocol version not supported"
					} else {
						expectedLocalError = "remote error: handshake failure"
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
					expectedError:      expectedError,
					expectedLocalError: expectedLocalError,
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
					expectedError:      expectedError,
					expectedLocalError: expectedLocalError,
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
					expectedError:      expectedError,
					expectedLocalError: expectedLocalError,
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
					expectedError:      expectedError,
					expectedLocalError: expectedLocalError,
				})
			}
		}
	}
}

func addD5BugTests() {
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "D5Bug-NoQuirk-Reject",
		config: Config{
			CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				SSL3RSAKeyExchange: true,
			},
		},
		shouldFail:    true,
		expectedError: ":TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "D5Bug-Quirk-Normal",
		config: Config{
			CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
		},
		flags: []string{"-tls-d5-bug"},
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "D5Bug-Quirk-Bug",
		config: Config{
			CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			Bugs: ProtocolBugs{
				SSL3RSAKeyExchange: true,
			},
		},
		flags: []string{"-tls-d5-bug"},
	})
}

func addExtensionTests() {
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "DuplicateExtensionClient",
		config: Config{
			Bugs: ProtocolBugs{
				DuplicateExtension: true,
			},
		},
		shouldFail:         true,
		expectedLocalError: "remote error: error decoding message",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "DuplicateExtensionServer",
		config: Config{
			Bugs: ProtocolBugs{
				DuplicateExtension: true,
			},
		},
		shouldFail:         true,
		expectedLocalError: "remote error: error decoding message",
	})
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "ServerNameExtensionClient",
		config: Config{
			Bugs: ProtocolBugs{
				ExpectServerName: "example.com",
			},
		},
		flags: []string{"-host-name", "example.com"},
	})
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "ServerNameExtensionClientMismatch",
		config: Config{
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
		name:     "ServerNameExtensionClientMissing",
		config: Config{
			Bugs: ProtocolBugs{
				ExpectServerName: "missing.com",
			},
		},
		shouldFail:         true,
		expectedLocalError: "tls: unexpected server name",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ServerNameExtensionServer",
		config: Config{
			ServerName: "example.com",
		},
		flags:         []string{"-expect-server-name", "example.com"},
		resumeSession: true,
	})
	testCases = append(testCases, testCase{
		testType: clientTest,
		name:     "ALPNClient",
		config: Config{
			NextProtos: []string{"foo"},
		},
		flags: []string{
			"-advertise-alpn", "\x03foo\x03bar\x03baz",
			"-expect-alpn", "foo",
		},
		expectedNextProto:     "foo",
		expectedNextProtoType: alpn,
		resumeSession:         true,
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ALPNServer",
		config: Config{
			NextProtos: []string{"foo", "bar", "baz"},
		},
		flags: []string{
			"-expect-advertised-alpn", "\x03foo\x03bar\x03baz",
			"-select-alpn", "foo",
		},
		expectedNextProto:     "foo",
		expectedNextProtoType: alpn,
		resumeSession:         true,
	})
	// Test that the server prefers ALPN over NPN.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ALPNServer-Preferred",
		config: Config{
			NextProtos: []string{"foo", "bar", "baz"},
		},
		flags: []string{
			"-expect-advertised-alpn", "\x03foo\x03bar\x03baz",
			"-select-alpn", "foo",
			"-advertise-npn", "\x03foo\x03bar\x03baz",
		},
		expectedNextProto:     "foo",
		expectedNextProtoType: alpn,
		resumeSession:         true,
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ALPNServer-Preferred-Swapped",
		config: Config{
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
		resumeSession:         true,
	})
	// Resume with a corrupt ticket.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "CorruptTicket",
		config: Config{
			Bugs: ProtocolBugs{
				CorruptTicket: true,
			},
		},
		resumeSession: true,
		flags:         []string{"-expect-session-miss"},
	})
	// Resume with an oversized session id.
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "OversizedSessionId",
		config: Config{
			Bugs: ProtocolBugs{
				OversizedSessionId: true,
			},
		},
		resumeSession: true,
		shouldFail:    true,
		expectedError: ":DECODE_ERROR:",
	})
	// Basic DTLS-SRTP tests. Include fake profiles to ensure they
	// are ignored.
	testCases = append(testCases, testCase{
		protocol: dtls,
		name:     "SRTP-Client",
		config: Config{
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
		name:     "SRTP-Server",
		config: Config{
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
		name:     "SRTP-Server-IgnoreMKI",
		config: Config{
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
		name:     "SRTP-Server-NoMatch",
		config: Config{
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
		name:     "SRTP-Client-NoMatch",
		config: Config{
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
	// Test OCSP stapling and SCT list.
	testCases = append(testCases, testCase{
		name: "OCSPStapling",
		flags: []string{
			"-enable-ocsp-stapling",
			"-expect-ocsp-response",
			base64.StdEncoding.EncodeToString(testOCSPResponse),
		},
	})
	testCases = append(testCases, testCase{
		name: "SignedCertificateTimestampList",
		flags: []string{
			"-enable-signed-cert-timestamps",
			"-expect-signed-cert-timestamps",
			base64.StdEncoding.EncodeToString(testSCTList),
		},
	})
}

func addResumptionVersionTests() {
	for _, sessionVers := range tlsVersions {
		for _, resumeVers := range tlsVersions {
			protocols := []protocol{tls}
			if sessionVers.hasDTLS && resumeVers.hasDTLS {
				protocols = append(protocols, dtls)
			}
			for _, protocol := range protocols {
				suffix := "-" + sessionVers.name + "-" + resumeVers.name
				if protocol == dtls {
					suffix += "-DTLS"
				}

				testCases = append(testCases, testCase{
					protocol:      protocol,
					name:          "Resume-Client" + suffix,
					resumeSession: true,
					config: Config{
						MaxVersion:   sessionVers.version,
						CipherSuites: []uint16{TLS_RSA_WITH_AES_128_CBC_SHA},
						Bugs: ProtocolBugs{
							AllowSessionVersionMismatch: true,
						},
					},
					expectedVersion: sessionVers.version,
					resumeConfig: &Config{
						MaxVersion:   resumeVers.version,
						CipherSuites: []uint16{TLS_RSA_WITH_AES_128_CBC_SHA},
						Bugs: ProtocolBugs{
							AllowSessionVersionMismatch: true,
						},
					},
					expectedResumeVersion: resumeVers.version,
				})

				testCases = append(testCases, testCase{
					protocol:      protocol,
					name:          "Resume-Client-NoResume" + suffix,
					flags:         []string{"-expect-session-miss"},
					resumeSession: true,
					config: Config{
						MaxVersion:   sessionVers.version,
						CipherSuites: []uint16{TLS_RSA_WITH_AES_128_CBC_SHA},
					},
					expectedVersion: sessionVers.version,
					resumeConfig: &Config{
						MaxVersion:   resumeVers.version,
						CipherSuites: []uint16{TLS_RSA_WITH_AES_128_CBC_SHA},
					},
					newSessionsOnResume:   true,
					expectedResumeVersion: resumeVers.version,
				})

				var flags []string
				if sessionVers.version != resumeVers.version {
					flags = append(flags, "-expect-session-miss")
				}
				testCases = append(testCases, testCase{
					protocol:      protocol,
					testType:      serverTest,
					name:          "Resume-Server" + suffix,
					flags:         flags,
					resumeSession: true,
					config: Config{
						MaxVersion:   sessionVers.version,
						CipherSuites: []uint16{TLS_RSA_WITH_AES_128_CBC_SHA},
					},
					expectedVersion: sessionVers.version,
					resumeConfig: &Config{
						MaxVersion:   resumeVers.version,
						CipherSuites: []uint16{TLS_RSA_WITH_AES_128_CBC_SHA},
					},
					expectedResumeVersion: resumeVers.version,
				})
			}
		}
	}
}

func addRenegotiationTests() {
	testCases = append(testCases, testCase{
		testType:        serverTest,
		name:            "Renegotiate-Server",
		flags:           []string{"-renegotiate"},
		shimWritesFirst: true,
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "Renegotiate-Server-EmptyExt",
		config: Config{
			Bugs: ProtocolBugs{
				EmptyRenegotiationInfo: true,
			},
		},
		flags:           []string{"-renegotiate"},
		shimWritesFirst: true,
		shouldFail:      true,
		expectedError:   ":RENEGOTIATION_MISMATCH:",
	})
	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "Renegotiate-Server-BadExt",
		config: Config{
			Bugs: ProtocolBugs{
				BadRenegotiationInfo: true,
			},
		},
		flags:           []string{"-renegotiate"},
		shimWritesFirst: true,
		shouldFail:      true,
		expectedError:   ":RENEGOTIATION_MISMATCH:",
	})
	testCases = append(testCases, testCase{
		testType:    serverTest,
		name:        "Renegotiate-Server-ClientInitiated",
		renegotiate: true,
	})
	testCases = append(testCases, testCase{
		testType:    serverTest,
		name:        "Renegotiate-Server-ClientInitiated-NoExt",
		renegotiate: true,
		config: Config{
			Bugs: ProtocolBugs{
				NoRenegotiationInfo: true,
			},
		},
		shouldFail:    true,
		expectedError: ":UNSAFE_LEGACY_RENEGOTIATION_DISABLED:",
	})
	testCases = append(testCases, testCase{
		testType:    serverTest,
		name:        "Renegotiate-Server-ClientInitiated-NoExt-Allowed",
		renegotiate: true,
		config: Config{
			Bugs: ProtocolBugs{
				NoRenegotiationInfo: true,
			},
		},
		flags: []string{"-allow-unsafe-legacy-renegotiation"},
	})
	// TODO(agl): test the renegotiation info SCSV.
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client",
		renegotiate: true,
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-EmptyExt",
		renegotiate: true,
		config: Config{
			Bugs: ProtocolBugs{
				EmptyRenegotiationInfo: true,
			},
		},
		shouldFail:    true,
		expectedError: ":RENEGOTIATION_MISMATCH:",
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-BadExt",
		renegotiate: true,
		config: Config{
			Bugs: ProtocolBugs{
				BadRenegotiationInfo: true,
			},
		},
		shouldFail:    true,
		expectedError: ":RENEGOTIATION_MISMATCH:",
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-SwitchCiphers",
		renegotiate: true,
		config: Config{
			CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA},
		},
		renegotiateCiphers: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-Client-SwitchCiphers2",
		renegotiate: true,
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		renegotiateCiphers: []uint16{TLS_RSA_WITH_RC4_128_SHA},
	})
	testCases = append(testCases, testCase{
		name:        "Renegotiate-SameClientVersion",
		renegotiate: true,
		config: Config{
			MaxVersion: VersionTLS10,
			Bugs: ProtocolBugs{
				RequireSameRenegoClientVersion: true,
			},
		},
	})
}

func addDTLSReplayTests() {
	// Test that sequence number replays are detected.
	testCases = append(testCases, testCase{
		protocol:     dtls,
		name:         "DTLS-Replay",
		replayWrites: true,
	})

	// Test the outgoing sequence number skipping by values larger
	// than the retransmit window.
	testCases = append(testCases, testCase{
		protocol: dtls,
		name:     "DTLS-Replay-LargeGaps",
		config: Config{
			Bugs: ProtocolBugs{
				SequenceNumberIncrement: 127,
			},
		},
		replayWrites: true,
	})
}

func addFastRadioPaddingTests() {
	testCases = append(testCases, testCase{
		protocol: tls,
		name:     "FastRadio-Padding",
		config: Config{
			Bugs: ProtocolBugs{
				RequireFastradioPadding: true,
			},
		},
		flags: []string{"-fastradio-padding"},
	})
	testCases = append(testCases, testCase{
		protocol: dtls,
		name:     "FastRadio-Padding-DTLS",
		config: Config{
			Bugs: ProtocolBugs{
				RequireFastradioPadding: true,
			},
		},
		flags: []string{"-fastradio-padding"},
	})
}

var testHashes = []struct {
	name string
	id   uint8
}{
	{"SHA1", hashSHA1},
	{"SHA224", hashSHA224},
	{"SHA256", hashSHA256},
	{"SHA384", hashSHA384},
	{"SHA512", hashSHA512},
}

func addSigningHashTests() {
	// Make sure each hash works. Include some fake hashes in the list and
	// ensure they're ignored.
	for _, hash := range testHashes {
		testCases = append(testCases, testCase{
			name: "SigningHash-ClientAuth-" + hash.name,
			config: Config{
				ClientAuth: RequireAnyClientCert,
				SignatureAndHashes: []signatureAndHash{
					{signatureRSA, 42},
					{signatureRSA, hash.id},
					{signatureRSA, 255},
				},
			},
			flags: []string{
				"-cert-file", rsaCertificateFile,
				"-key-file", rsaKeyFile,
			},
		})

		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "SigningHash-ServerKeyExchange-Sign-" + hash.name,
			config: Config{
				CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				SignatureAndHashes: []signatureAndHash{
					{signatureRSA, 42},
					{signatureRSA, hash.id},
					{signatureRSA, 255},
				},
			},
		})
	}

	// Test that hash resolution takes the signature type into account.
	testCases = append(testCases, testCase{
		name: "SigningHash-ClientAuth-SignatureType",
		config: Config{
			ClientAuth: RequireAnyClientCert,
			SignatureAndHashes: []signatureAndHash{
				{signatureECDSA, hashSHA512},
				{signatureRSA, hashSHA384},
				{signatureECDSA, hashSHA1},
			},
		},
		flags: []string{
			"-cert-file", rsaCertificateFile,
			"-key-file", rsaKeyFile,
		},
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SigningHash-ServerKeyExchange-SignatureType",
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			SignatureAndHashes: []signatureAndHash{
				{signatureECDSA, hashSHA512},
				{signatureRSA, hashSHA384},
				{signatureECDSA, hashSHA1},
			},
		},
	})

	// Test that, if the list is missing, the peer falls back to SHA-1.
	testCases = append(testCases, testCase{
		name: "SigningHash-ClientAuth-Fallback",
		config: Config{
			ClientAuth: RequireAnyClientCert,
			SignatureAndHashes: []signatureAndHash{
				{signatureRSA, hashSHA1},
			},
			Bugs: ProtocolBugs{
				NoSignatureAndHashes: true,
			},
		},
		flags: []string{
			"-cert-file", rsaCertificateFile,
			"-key-file", rsaKeyFile,
		},
	})

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "SigningHash-ServerKeyExchange-Fallback",
		config: Config{
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			SignatureAndHashes: []signatureAndHash{
				{signatureRSA, hashSHA1},
			},
			Bugs: ProtocolBugs{
				NoSignatureAndHashes: true,
			},
		},
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

func addDTLSRetransmitTests() {
	// Test that this is indeed the timeout schedule. Stress all
	// four patterns of handshake.
	for i := 1; i < len(timeouts); i++ {
		number := strconv.Itoa(i)
		testCases = append(testCases, testCase{
			protocol: dtls,
			name:     "DTLS-Retransmit-Client-" + number,
			config: Config{
				Bugs: ProtocolBugs{
					TimeoutSchedule: timeouts[:i],
				},
			},
			resumeSession: true,
			flags:         []string{"-async"},
		})
		testCases = append(testCases, testCase{
			protocol: dtls,
			testType: serverTest,
			name:     "DTLS-Retransmit-Server-" + number,
			config: Config{
				Bugs: ProtocolBugs{
					TimeoutSchedule: timeouts[:i],
				},
			},
			resumeSession: true,
			flags:         []string{"-async"},
		})
	}

	// Test that exceeding the timeout schedule hits a read
	// timeout.
	testCases = append(testCases, testCase{
		protocol: dtls,
		name:     "DTLS-Retransmit-Timeout",
		config: Config{
			Bugs: ProtocolBugs{
				TimeoutSchedule: timeouts,
			},
		},
		resumeSession: true,
		flags:         []string{"-async"},
		shouldFail:    true,
		expectedError: ":READ_TIMEOUT_EXPIRED:",
	})

	// Test that timeout handling has a fudge factor, due to API
	// problems.
	testCases = append(testCases, testCase{
		protocol: dtls,
		name:     "DTLS-Retransmit-Fudge",
		config: Config{
			Bugs: ProtocolBugs{
				TimeoutSchedule: []time.Duration{
					timeouts[0] - 10*time.Millisecond,
				},
			},
		},
		resumeSession: true,
		flags:         []string{"-async"},
	})

	// Test that the final Finished retransmitting isn't
	// duplicated if the peer badly fragments everything.
	testCases = append(testCases, testCase{
		testType: serverTest,
		protocol: dtls,
		name:     "DTLS-Retransmit-Fragmented",
		config: Config{
			Bugs: ProtocolBugs{
				TimeoutSchedule:          []time.Duration{timeouts[0]},
				MaxHandshakeRecordLength: 2,
			},
		},
		flags: []string{"-async"},
	})
}

func worker(statusChan chan statusMsg, c chan *testCase, buildDir string, wg *sync.WaitGroup) {
	defer wg.Done()

	for test := range c {
		var err error

		if *mallocTest < 0 {
			statusChan <- statusMsg{test: test, started: true}
			err = runTest(test, buildDir, -1)
		} else {
			for mallocNumToFail := int64(*mallocTest); ; mallocNumToFail++ {
				statusChan <- statusMsg{test: test, started: true}
				if err = runTest(test, buildDir, mallocNumToFail); err != errMoreMallocs {
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
	addMinimumVersionTests()
	addD5BugTests()
	addExtensionTests()
	addResumptionVersionTests()
	addExtendedMasterSecretTests()
	addRenegotiationTests()
	addDTLSReplayTests()
	addSigningHashTests()
	addFastRadioPaddingTests()
	addDTLSRetransmitTests()
	for _, async := range []bool{false, true} {
		for _, splitHandshake := range []bool{false, true} {
			for _, protocol := range []protocol{tls, dtls} {
				addStateMachineCoverageTests(async, splitHandshake, protocol)
			}
		}
	}

	var wg sync.WaitGroup

	numWorkers := *flagNumWorkers

	statusChan := make(chan statusMsg, numWorkers)
	testChan := make(chan *testCase, numWorkers)
	doneChan := make(chan *testOutput)

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
	testOutput := <-doneChan

	fmt.Printf("\n")

	if *jsonOutput != "" {
		if err := testOutput.writeTo(*jsonOutput); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
	}
}
