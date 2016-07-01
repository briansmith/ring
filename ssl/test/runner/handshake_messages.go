// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner

import "bytes"

func writeLen(buf []byte, v, size int) {
	for i := 0; i < size; i++ {
		buf[size-i-1] = byte(v)
		v >>= 8
	}
	if v != 0 {
		panic("length is too long")
	}
}

type byteBuilder struct {
	buf       *[]byte
	start     int
	prefixLen int
	child     *byteBuilder
}

func newByteBuilder() *byteBuilder {
	buf := make([]byte, 0, 32)
	return &byteBuilder{buf: &buf}
}

func (bb *byteBuilder) len() int {
	return len(*bb.buf) - bb.start - bb.prefixLen
}

func (bb *byteBuilder) flush() {
	if bb.child == nil {
		return
	}
	bb.child.flush()
	writeLen((*bb.buf)[bb.child.start:], bb.child.len(), bb.child.prefixLen)
	bb.child = nil
	return
}

func (bb *byteBuilder) finish() []byte {
	bb.flush()
	return *bb.buf
}

func (bb *byteBuilder) addU8(u uint8) {
	bb.flush()
	*bb.buf = append(*bb.buf, u)
}

func (bb *byteBuilder) addU16(u uint16) {
	bb.flush()
	*bb.buf = append(*bb.buf, byte(u>>8), byte(u))
}

func (bb *byteBuilder) addU24(u int) {
	bb.flush()
	*bb.buf = append(*bb.buf, byte(u>>16), byte(u>>8), byte(u))
}

func (bb *byteBuilder) addU32(u uint32) {
	bb.flush()
	*bb.buf = append(*bb.buf, byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

func (bb *byteBuilder) addU8LengthPrefixed() *byteBuilder {
	return bb.createChild(1)
}

func (bb *byteBuilder) addU16LengthPrefixed() *byteBuilder {
	return bb.createChild(2)
}

func (bb *byteBuilder) addU24LengthPrefixed() *byteBuilder {
	return bb.createChild(3)
}

func (bb *byteBuilder) addBytes(b []byte) {
	bb.flush()
	*bb.buf = append(*bb.buf, b...)
}

func (bb *byteBuilder) createChild(lengthPrefixSize int) *byteBuilder {
	bb.flush()
	bb.child = &byteBuilder{
		buf:       bb.buf,
		start:     len(*bb.buf),
		prefixLen: lengthPrefixSize,
	}
	for i := 0; i < lengthPrefixSize; i++ {
		*bb.buf = append(*bb.buf, 0)
	}
	return bb.child
}

func (bb *byteBuilder) discardChild() {
	if bb.child != nil {
		return
	}
	bb.child = nil
	*bb.buf = (*bb.buf)[:bb.start]
}

type clientHelloMsg struct {
	raw                     []byte
	isDTLS                  bool
	vers                    uint16
	random                  []byte
	sessionId               []byte
	cookie                  []byte
	cipherSuites            []uint16
	compressionMethods      []uint8
	nextProtoNeg            bool
	serverName              string
	ocspStapling            bool
	supportedCurves         []CurveID
	supportedPoints         []uint8
	ticketSupported         bool
	sessionTicket           []uint8
	signatureAlgorithms     []signatureAlgorithm
	secureRenegotiation     []byte
	alpnProtocols           []string
	duplicateExtension      bool
	channelIDSupported      bool
	npnLast                 bool
	extendedMasterSecret    bool
	srtpProtectionProfiles  []uint16
	srtpMasterKeyIdentifier string
	sctListSupported        bool
	customExtension         string
}

func (m *clientHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*clientHelloMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.isDTLS == m1.isDTLS &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		bytes.Equal(m.cookie, m1.cookie) &&
		eqUint16s(m.cipherSuites, m1.cipherSuites) &&
		bytes.Equal(m.compressionMethods, m1.compressionMethods) &&
		m.nextProtoNeg == m1.nextProtoNeg &&
		m.serverName == m1.serverName &&
		m.ocspStapling == m1.ocspStapling &&
		eqCurveIDs(m.supportedCurves, m1.supportedCurves) &&
		bytes.Equal(m.supportedPoints, m1.supportedPoints) &&
		m.ticketSupported == m1.ticketSupported &&
		bytes.Equal(m.sessionTicket, m1.sessionTicket) &&
		eqSignatureAlgorithms(m.signatureAlgorithms, m1.signatureAlgorithms) &&
		bytes.Equal(m.secureRenegotiation, m1.secureRenegotiation) &&
		(m.secureRenegotiation == nil) == (m1.secureRenegotiation == nil) &&
		eqStrings(m.alpnProtocols, m1.alpnProtocols) &&
		m.duplicateExtension == m1.duplicateExtension &&
		m.channelIDSupported == m1.channelIDSupported &&
		m.npnLast == m1.npnLast &&
		m.extendedMasterSecret == m1.extendedMasterSecret &&
		eqUint16s(m.srtpProtectionProfiles, m1.srtpProtectionProfiles) &&
		m.srtpMasterKeyIdentifier == m1.srtpMasterKeyIdentifier &&
		m.sctListSupported == m1.sctListSupported &&
		m.customExtension == m1.customExtension
}

func (m *clientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	handshakeMsg := newByteBuilder()
	handshakeMsg.addU8(typeClientHello)
	hello := handshakeMsg.addU24LengthPrefixed()
	vers := versionToWire(m.vers, m.isDTLS)
	hello.addU16(vers)
	hello.addBytes(m.random)
	sessionId := hello.addU8LengthPrefixed()
	sessionId.addBytes(m.sessionId)
	if m.isDTLS {
		cookie := hello.addU8LengthPrefixed()
		cookie.addBytes(m.cookie)
	}
	cipherSuites := hello.addU16LengthPrefixed()
	for _, suite := range m.cipherSuites {
		cipherSuites.addU16(suite)
	}
	compressionMethods := hello.addU8LengthPrefixed()
	compressionMethods.addBytes(m.compressionMethods)

	extensions := hello.addU16LengthPrefixed()
	if m.duplicateExtension {
		// Add a duplicate bogus extension at the beginning and end.
		extensions.addU16(0xffff)
		extensions.addU16(0) // 0-length for empty extension
	}
	if m.nextProtoNeg && !m.npnLast {
		extensions.addU16(extensionNextProtoNeg)
		extensions.addU16(0) // The length is always 0
	}
	if len(m.serverName) > 0 {
		extensions.addU16(extensionServerName)
		serverNameList := extensions.addU16LengthPrefixed()

		// RFC 3546, section 3.1
		//
		// struct {
		//     NameType name_type;
		//     select (name_type) {
		//         case host_name: HostName;
		//     } name;
		// } ServerName;
		//
		// enum {
		//     host_name(0), (255)
		// } NameType;
		//
		// opaque HostName<1..2^16-1>;
		//
		// struct {
		//     ServerName server_name_list<1..2^16-1>
		// } ServerNameList;

		serverName := serverNameList.addU16LengthPrefixed()
		serverName.addU8(0) // NameType host_name(0)
		hostName := serverName.addU16LengthPrefixed()
		hostName.addBytes([]byte(m.serverName))
	}
	if m.ocspStapling {
		extensions.addU16(extensionStatusRequest)
		certificateStatusRequest := extensions.addU16LengthPrefixed()

		// RFC 4366, section 3.6
		certificateStatusRequest.addU8(1) // OCSP type
		// Two zero valued uint16s for the two lengths.
		certificateStatusRequest.addU16(0) // ResponderID length
		certificateStatusRequest.addU16(0) // Extensions length
	}
	if len(m.supportedCurves) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.1.1
		extensions.addU16(extensionSupportedCurves)
		supportedCurvesList := extensions.addU16LengthPrefixed()
		supportedCurves := supportedCurvesList.addU16LengthPrefixed()
		for _, curve := range m.supportedCurves {
			supportedCurves.addU16(uint16(curve))
		}
	}
	if len(m.supportedPoints) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.1.2
		extensions.addU16(extensionSupportedPoints)
		supportedPointsList := extensions.addU16LengthPrefixed()
		supportedPoints := supportedPointsList.addU8LengthPrefixed()
		for _, pointFormat := range m.supportedPoints {
			supportedPoints.addU8(pointFormat)
		}
	}
	if m.ticketSupported {
		// http://tools.ietf.org/html/rfc5077#section-3.2
		extensions.addU16(extensionSessionTicket)
		sessionTicketExtension := extensions.addU16LengthPrefixed()
		sessionTicketExtension.addBytes(m.sessionTicket)
	}
	if len(m.signatureAlgorithms) > 0 {
		// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		extensions.addU16(extensionSignatureAlgorithms)
		signatureAlgorithmsExtension := extensions.addU16LengthPrefixed()
		signatureAlgorithms := signatureAlgorithmsExtension.addU16LengthPrefixed()
		for _, sigAlg := range m.signatureAlgorithms {
			signatureAlgorithms.addU16(uint16(sigAlg))
		}
	}
	if m.secureRenegotiation != nil {
		extensions.addU16(extensionRenegotiationInfo)
		secureRenegoExt := extensions.addU16LengthPrefixed()
		secureRenego := secureRenegoExt.addU8LengthPrefixed()
		secureRenego.addBytes(m.secureRenegotiation)
	}
	if len(m.alpnProtocols) > 0 {
		// https://tools.ietf.org/html/rfc7301#section-3.1
		extensions.addU16(extensionALPN)
		alpnExtension := extensions.addU16LengthPrefixed()

		protocolNameList := alpnExtension.addU16LengthPrefixed()
		for _, s := range m.alpnProtocols {
			protocolName := protocolNameList.addU8LengthPrefixed()
			protocolName.addBytes([]byte(s))
		}
	}
	if m.channelIDSupported {
		extensions.addU16(extensionChannelID)
		extensions.addU16(0) // Length is always 0
	}
	if m.nextProtoNeg && m.npnLast {
		extensions.addU16(extensionNextProtoNeg)
		extensions.addU16(0) // Length is always 0
	}
	if m.duplicateExtension {
		// Add a duplicate bogus extension at the beginning and end.
		extensions.addU16(0xffff)
		extensions.addU16(0)
	}
	if m.extendedMasterSecret {
		// https://tools.ietf.org/html/rfc7627
		extensions.addU16(extensionExtendedMasterSecret)
		extensions.addU16(0) // Length is always 0
	}
	if len(m.srtpProtectionProfiles) > 0 {
		// https://tools.ietf.org/html/rfc5764#section-4.1.1
		extensions.addU16(extensionUseSRTP)
		useSrtpExt := extensions.addU16LengthPrefixed()

		srtpProtectionProfiles := useSrtpExt.addU16LengthPrefixed()
		for _, p := range m.srtpProtectionProfiles {
			// An SRTPProtectionProfile is defined as uint8[2],
			// not uint16. For some reason, we're storing it
			// as a uint16.
			srtpProtectionProfiles.addU8(byte(p >> 8))
			srtpProtectionProfiles.addU8(byte(p))
		}
		srtpMki := useSrtpExt.addU8LengthPrefixed()
		srtpMki.addBytes([]byte(m.srtpMasterKeyIdentifier))
	}
	if m.sctListSupported {
		extensions.addU16(extensionSignedCertificateTimestamp)
		extensions.addU16(0) // Length is always 0
	}
	if l := len(m.customExtension); l > 0 {
		extensions.addU16(extensionCustom)
		customExt := extensions.addU16LengthPrefixed()
		customExt.addBytes([]byte(m.customExtension))
	}

	if extensions.len() == 0 {
		hello.discardChild()
	}

	m.raw = handshakeMsg.finish()
	return m.raw
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.raw = data
	m.vers = wireToVersion(uint16(data[4])<<8|uint16(data[5]), m.isDTLS)
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if m.isDTLS {
		if len(data) < 1 {
			return false
		}
		cookieLen := int(data[0])
		if cookieLen > 32 || len(data) < 1+cookieLen {
			return false
		}
		m.cookie = data[1 : 1+cookieLen]
		data = data[1+cookieLen:]
	}
	if len(data) < 2 {
		return false
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}
	numCipherSuites := cipherSuiteLen / 2
	m.cipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
		if m.cipherSuites[i] == scsvRenegotiation {
			m.secureRenegotiation = []byte{}
		}
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false
	}
	m.compressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]

	m.nextProtoNeg = false
	m.serverName = ""
	m.ocspStapling = false
	m.ticketSupported = false
	m.sessionTicket = nil
	m.signatureAlgorithms = nil
	m.alpnProtocols = nil
	m.extendedMasterSecret = false
	m.customExtension = ""

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionServerName:
			if length < 2 {
				return false
			}
			numNames := int(data[0])<<8 | int(data[1])
			d := data[2:]
			for i := 0; i < numNames; i++ {
				if len(d) < 3 {
					return false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return false
				}
				if nameType == 0 {
					m.serverName = string(d[0:nameLen])
					break
				}
				d = d[nameLen:]
			}
		case extensionNextProtoNeg:
			if length > 0 {
				return false
			}
			m.nextProtoNeg = true
		case extensionStatusRequest:
			m.ocspStapling = length > 0 && data[0] == statusTypeOCSP
		case extensionSupportedCurves:
			// http://tools.ietf.org/html/rfc4492#section-5.5.1
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l%2 == 1 || length != l+2 {
				return false
			}
			numCurves := l / 2
			m.supportedCurves = make([]CurveID, numCurves)
			d := data[2:]
			for i := 0; i < numCurves; i++ {
				m.supportedCurves[i] = CurveID(d[0])<<8 | CurveID(d[1])
				d = d[2:]
			}
		case extensionSupportedPoints:
			// http://tools.ietf.org/html/rfc4492#section-5.5.2
			if length < 1 {
				return false
			}
			l := int(data[0])
			if length != l+1 {
				return false
			}
			m.supportedPoints = make([]uint8, l)
			copy(m.supportedPoints, data[1:])
		case extensionSessionTicket:
			// http://tools.ietf.org/html/rfc5077#section-3.2
			m.ticketSupported = true
			m.sessionTicket = data[:length]
		case extensionSignatureAlgorithms:
			// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
			if length < 2 || length&1 != 0 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			n := l / 2
			d := data[2:]
			m.signatureAlgorithms = make([]signatureAlgorithm, n)
			for i := range m.signatureAlgorithms {
				m.signatureAlgorithms[i] = signatureAlgorithm(d[0])<<8 | signatureAlgorithm(d[1])
				d = d[2:]
			}
		case extensionRenegotiationInfo:
			if length < 1 || length != int(data[0])+1 {
				return false
			}
			m.secureRenegotiation = data[1:length]
		case extensionALPN:
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			d := data[2:length]
			for len(d) != 0 {
				stringLen := int(d[0])
				d = d[1:]
				if stringLen == 0 || stringLen > len(d) {
					return false
				}
				m.alpnProtocols = append(m.alpnProtocols, string(d[:stringLen]))
				d = d[stringLen:]
			}
		case extensionChannelID:
			if length > 0 {
				return false
			}
			m.channelIDSupported = true
		case extensionExtendedMasterSecret:
			if length != 0 {
				return false
			}
			m.extendedMasterSecret = true
		case extensionUseSRTP:
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l > length-2 || l%2 != 0 {
				return false
			}
			n := l / 2
			m.srtpProtectionProfiles = make([]uint16, n)
			d := data[2:length]
			for i := 0; i < n; i++ {
				m.srtpProtectionProfiles[i] = uint16(d[0])<<8 | uint16(d[1])
				d = d[2:]
			}
			if len(d) < 1 || int(d[0]) != len(d)-1 {
				return false
			}
			m.srtpMasterKeyIdentifier = string(d[1:])
		case extensionSignedCertificateTimestamp:
			if length != 0 {
				return false
			}
			m.sctListSupported = true
		case extensionCustom:
			m.customExtension = string(data[:length])
		}
		data = data[length:]
	}

	return true
}

type serverHelloMsg struct {
	raw               []byte
	isDTLS            bool
	vers              uint16
	random            []byte
	sessionId         []byte
	cipherSuite       uint16
	compressionMethod uint8
	extensions        serverExtensions
}

func (m *serverHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	handshakeMsg := newByteBuilder()
	handshakeMsg.addU8(typeServerHello)
	hello := handshakeMsg.addU24LengthPrefixed()
	vers := versionToWire(m.vers, m.isDTLS)
	hello.addU16(vers)
	hello.addBytes(m.random)
	sessionId := hello.addU8LengthPrefixed()
	sessionId.addBytes(m.sessionId)
	hello.addU16(m.cipherSuite)
	hello.addU8(m.compressionMethod)

	extensions := hello.addU16LengthPrefixed()

	m.extensions.marshal(extensions)

	if extensions.len() == 0 {
		hello.discardChild()
	}

	m.raw = handshakeMsg.finish()
	return m.raw
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.raw = data
	m.vers = wireToVersion(uint16(data[4])<<8|uint16(data[5]), m.isDTLS)
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 3 {
		return false
	}
	m.cipherSuite = uint16(data[0])<<8 | uint16(data[1])
	m.compressionMethod = data[2]
	data = data[3:]

	if len(data) == 0 {
		// ServerHello is optionally followed by extension data
		m.extensions = serverExtensions{}
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) != extensionsLength {
		return false
	}

	if !m.extensions.unmarshal(data) {
		return false
	}

	return true
}

type serverExtensions struct {
	nextProtoNeg            bool
	nextProtos              []string
	ocspStapling            bool
	ticketSupported         bool
	secureRenegotiation     []byte
	alpnProtocol            string
	alpnProtocolEmpty       bool
	duplicateExtension      bool
	channelIDRequested      bool
	extendedMasterSecret    bool
	srtpProtectionProfile   uint16
	srtpMasterKeyIdentifier string
	sctList                 []byte
	customExtension         string
	npnLast                 bool
}

func (m *serverExtensions) marshal(extensions *byteBuilder) {
	if m.duplicateExtension {
		// Add a duplicate bogus extension at the beginning and end.
		extensions.addU16(0xffff)
		extensions.addU16(0) // length = 0 for empty extension
	}
	if m.nextProtoNeg && !m.npnLast {
		extensions.addU16(extensionNextProtoNeg)
		extension := extensions.addU16LengthPrefixed()

		for _, v := range m.nextProtos {
			if len(v) > 255 {
				v = v[:255]
			}
			npn := extension.addU8LengthPrefixed()
			npn.addBytes([]byte(v))
		}
	}
	if m.ocspStapling {
		extensions.addU16(extensionStatusRequest)
		extensions.addU16(0)
	}
	if m.ticketSupported {
		extensions.addU16(extensionSessionTicket)
		extensions.addU16(0)
	}
	if m.secureRenegotiation != nil {
		extensions.addU16(extensionRenegotiationInfo)
		extension := extensions.addU16LengthPrefixed()
		secureRenego := extension.addU8LengthPrefixed()
		secureRenego.addBytes(m.secureRenegotiation)
	}
	if len(m.alpnProtocol) > 0 || m.alpnProtocolEmpty {
		extensions.addU16(extensionALPN)
		extension := extensions.addU16LengthPrefixed()

		protocolNameList := extension.addU16LengthPrefixed()
		protocolName := protocolNameList.addU8LengthPrefixed()
		protocolName.addBytes([]byte(m.alpnProtocol))
	}
	if m.channelIDRequested {
		extensions.addU16(extensionChannelID)
		extensions.addU16(0)
	}
	if m.duplicateExtension {
		// Add a duplicate bogus extension at the beginning and end.
		extensions.addU16(0xffff)
		extensions.addU16(0)
	}
	if m.extendedMasterSecret {
		extensions.addU16(extensionExtendedMasterSecret)
		extensions.addU16(0)
	}
	if m.srtpProtectionProfile != 0 {
		extensions.addU16(extensionUseSRTP)
		extension := extensions.addU16LengthPrefixed()

		srtpProtectionProfiles := extension.addU16LengthPrefixed()
		srtpProtectionProfiles.addU8(byte(m.srtpProtectionProfile >> 8))
		srtpProtectionProfiles.addU8(byte(m.srtpProtectionProfile))
		srtpMki := extension.addU8LengthPrefixed()
		srtpMki.addBytes([]byte(m.srtpMasterKeyIdentifier))
	}
	if m.sctList != nil {
		extensions.addU16(extensionSignedCertificateTimestamp)
		extension := extensions.addU16LengthPrefixed()
		extension.addBytes(m.sctList)
	}
	if l := len(m.customExtension); l > 0 {
		extensions.addU16(extensionCustom)
		customExt := extensions.addU16LengthPrefixed()
		customExt.addBytes([]byte(m.customExtension))
	}
	if m.nextProtoNeg && m.npnLast {
		extensions.addU16(extensionNextProtoNeg)
		extension := extensions.addU16LengthPrefixed()

		for _, v := range m.nextProtos {
			if len(v) > 255 {
				v = v[0:255]
			}
			npn := extension.addU8LengthPrefixed()
			npn.addBytes([]byte(v))
		}
	}
}

func (m *serverExtensions) unmarshal(data []byte) bool {
	// Reset all fields.
	*m = serverExtensions{}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionNextProtoNeg:
			m.nextProtoNeg = true
			d := data[:length]
			for len(d) > 0 {
				l := int(d[0])
				d = d[1:]
				if l == 0 || l > len(d) {
					return false
				}
				m.nextProtos = append(m.nextProtos, string(d[:l]))
				d = d[l:]
			}
		case extensionStatusRequest:
			if length > 0 {
				return false
			}
			m.ocspStapling = true
		case extensionSessionTicket:
			if length > 0 {
				return false
			}
			m.ticketSupported = true
		case extensionRenegotiationInfo:
			if length < 1 || length != int(data[0])+1 {
				return false
			}
			m.secureRenegotiation = data[1:length]
		case extensionALPN:
			d := data[:length]
			if len(d) < 3 {
				return false
			}
			l := int(d[0])<<8 | int(d[1])
			if l != len(d)-2 {
				return false
			}
			d = d[2:]
			l = int(d[0])
			if l != len(d)-1 {
				return false
			}
			d = d[1:]
			m.alpnProtocol = string(d)
			m.alpnProtocolEmpty = len(d) == 0
		case extensionChannelID:
			if length > 0 {
				return false
			}
			m.channelIDRequested = true
		case extensionExtendedMasterSecret:
			if length != 0 {
				return false
			}
			m.extendedMasterSecret = true
		case extensionUseSRTP:
			if length < 2+2+1 {
				return false
			}
			if data[0] != 0 || data[1] != 2 {
				return false
			}
			m.srtpProtectionProfile = uint16(data[2])<<8 | uint16(data[3])
			d := data[4:length]
			l := int(d[0])
			if l != len(d)-1 {
				return false
			}
			m.srtpMasterKeyIdentifier = string(d[1:])
		case extensionSignedCertificateTimestamp:
			m.sctList = data[:length]
		case extensionCustom:
			m.customExtension = string(data[:length])
		}
		data = data[length:]
	}

	return true
}

type certificateMsg struct {
	raw          []byte
	certificates [][]byte
}

func (m *certificateMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	certMsg := newByteBuilder()
	certMsg.addU8(typeCertificate)
	certificate := certMsg.addU24LengthPrefixed()
	certificateList := certificate.addU24LengthPrefixed()
	for _, cert := range m.certificates {
		certEntry := certificateList.addU24LengthPrefixed()
		certEntry.addBytes(cert)
	}

	m.raw = certMsg.finish()
	return m.raw
}

func (m *certificateMsg) unmarshal(data []byte) bool {
	if len(data) < 7 {
		return false
	}

	m.raw = data
	certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
	if uint32(len(data)) != certsLen+7 {
		return false
	}

	numCerts := 0
	d := data[7:]
	for certsLen > 0 {
		if len(d) < 4 {
			return false
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return false
		}
		d = d[3+certLen:]
		certsLen -= 3 + certLen
		numCerts++
	}

	m.certificates = make([][]byte, numCerts)
	d = data[7:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return true
}

type serverKeyExchangeMsg struct {
	raw []byte
	key []byte
}

func (m *serverKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.key)
	x := make([]byte, length+4)
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.key)

	m.raw = x
	return x
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	m.key = data[4:]
	return true
}

type certificateStatusMsg struct {
	raw        []byte
	statusType uint8
	response   []byte
}

func (m *certificateStatusMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var x []byte
	if m.statusType == statusTypeOCSP {
		x = make([]byte, 4+4+len(m.response))
		x[0] = typeCertificateStatus
		l := len(m.response) + 4
		x[1] = byte(l >> 16)
		x[2] = byte(l >> 8)
		x[3] = byte(l)
		x[4] = statusTypeOCSP

		l -= 4
		x[5] = byte(l >> 16)
		x[6] = byte(l >> 8)
		x[7] = byte(l)
		copy(x[8:], m.response)
	} else {
		x = []byte{typeCertificateStatus, 0, 0, 1, m.statusType}
	}

	m.raw = x
	return x
}

func (m *certificateStatusMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 5 {
		return false
	}
	m.statusType = data[4]

	m.response = nil
	if m.statusType == statusTypeOCSP {
		if len(data) < 8 {
			return false
		}
		respLen := uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
		if uint32(len(data)) != 4+4+respLen {
			return false
		}
		m.response = data[8:]
	}
	return true
}

type serverHelloDoneMsg struct{}

func (m *serverHelloDoneMsg) marshal() []byte {
	x := make([]byte, 4)
	x[0] = typeServerHelloDone
	return x
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

type clientKeyExchangeMsg struct {
	raw        []byte
	ciphertext []byte
}

func (m *clientKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	m.raw = x
	return x
}

func (m *clientKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-4 {
		return false
	}
	m.ciphertext = data[4:]
	return true
}

type finishedMsg struct {
	raw        []byte
	verifyData []byte
}

func (m *finishedMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	x = make([]byte, 4+len(m.verifyData))
	x[0] = typeFinished
	x[3] = byte(len(m.verifyData))
	copy(x[4:], m.verifyData)
	m.raw = x
	return
}

func (m *finishedMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	m.verifyData = data[4:]
	return true
}

type nextProtoMsg struct {
	raw   []byte
	proto string
}

func (m *nextProtoMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	l := len(m.proto)
	if l > 255 {
		l = 255
	}

	padding := 32 - (l+2)%32
	length := l + padding + 2
	x := make([]byte, length+4)
	x[0] = typeNextProtocol
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	y := x[4:]
	y[0] = byte(l)
	copy(y[1:], []byte(m.proto[0:l]))
	y = y[1+l:]
	y[0] = byte(padding)

	m.raw = x

	return x
}

func (m *nextProtoMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 5 {
		return false
	}
	data = data[4:]
	protoLen := int(data[0])
	data = data[1:]
	if len(data) < protoLen {
		return false
	}
	m.proto = string(data[0:protoLen])
	data = data[protoLen:]

	if len(data) < 1 {
		return false
	}
	paddingLen := int(data[0])
	data = data[1:]
	if len(data) != paddingLen {
		return false
	}

	return true
}

type certificateRequestMsg struct {
	raw []byte
	// hasSignatureAlgorithm indicates whether this message includes a list
	// of signature and hash functions. This change was introduced with TLS
	// 1.2.
	hasSignatureAlgorithm bool

	certificateTypes       []byte
	signatureAlgorithms    []signatureAlgorithm
	certificateAuthorities [][]byte
}

func (m *certificateRequestMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc4346#section-7.4.4
	builder := newByteBuilder()
	builder.addU8(typeCertificateRequest)
	body := builder.addU24LengthPrefixed()

	certificateTypes := body.addU8LengthPrefixed()
	certificateTypes.addBytes(m.certificateTypes)

	if m.hasSignatureAlgorithm {
		signatureAlgorithms := body.addU16LengthPrefixed()
		for _, sigAlg := range m.signatureAlgorithms {
			signatureAlgorithms.addU16(uint16(sigAlg))
		}
	}

	certificateAuthorities := body.addU16LengthPrefixed()
	for _, ca := range m.certificateAuthorities {
		caEntry := certificateAuthorities.addU16LengthPrefixed()
		caEntry.addBytes(ca)
	}

	m.raw = builder.finish()
	return m.raw
}

func (m *certificateRequestMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 5 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	numCertTypes := int(data[4])
	data = data[5:]
	if numCertTypes == 0 || len(data) <= numCertTypes {
		return false
	}

	m.certificateTypes = make([]byte, numCertTypes)
	if copy(m.certificateTypes, data) != numCertTypes {
		return false
	}

	data = data[numCertTypes:]

	if m.hasSignatureAlgorithm {
		if len(data) < 2 {
			return false
		}
		sigAlgsLen := uint16(data[0])<<8 | uint16(data[1])
		data = data[2:]
		if sigAlgsLen&1 != 0 {
			return false
		}
		if len(data) < int(sigAlgsLen) {
			return false
		}
		numSigAlgs := sigAlgsLen / 2
		m.signatureAlgorithms = make([]signatureAlgorithm, numSigAlgs)
		for i := range m.signatureAlgorithms {
			m.signatureAlgorithms[i] = signatureAlgorithm(data[0])<<8 | signatureAlgorithm(data[1])
			data = data[2:]
		}
	}

	if len(data) < 2 {
		return false
	}
	casLength := uint16(data[0])<<8 | uint16(data[1])
	data = data[2:]
	if len(data) < int(casLength) {
		return false
	}
	cas := make([]byte, casLength)
	copy(cas, data)
	data = data[casLength:]

	m.certificateAuthorities = nil
	for len(cas) > 0 {
		if len(cas) < 2 {
			return false
		}
		caLen := uint16(cas[0])<<8 | uint16(cas[1])
		cas = cas[2:]

		if len(cas) < int(caLen) {
			return false
		}

		m.certificateAuthorities = append(m.certificateAuthorities, cas[:caLen])
		cas = cas[caLen:]
	}
	if len(data) > 0 {
		return false
	}

	return true
}

type certificateVerifyMsg struct {
	raw                   []byte
	hasSignatureAlgorithm bool
	signatureAlgorithm    signatureAlgorithm
	signature             []byte
}

func (m *certificateVerifyMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc4346#section-7.4.8
	siglength := len(m.signature)
	length := 2 + siglength
	if m.hasSignatureAlgorithm {
		length += 2
	}
	x = make([]byte, 4+length)
	x[0] = typeCertificateVerify
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	y := x[4:]
	if m.hasSignatureAlgorithm {
		y[0] = byte(m.signatureAlgorithm >> 8)
		y[1] = byte(m.signatureAlgorithm)
		y = y[2:]
	}
	y[0] = uint8(siglength >> 8)
	y[1] = uint8(siglength)
	copy(y[2:], m.signature)

	m.raw = x

	return
}

func (m *certificateVerifyMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 6 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	data = data[4:]
	if m.hasSignatureAlgorithm {
		m.signatureAlgorithm = signatureAlgorithm(data[0])<<8 | signatureAlgorithm(data[1])
		data = data[2:]
	}

	if len(data) < 2 {
		return false
	}
	siglength := int(data[0])<<8 + int(data[1])
	data = data[2:]
	if len(data) != siglength {
		return false
	}

	m.signature = data

	return true
}

type newSessionTicketMsg struct {
	raw    []byte
	ticket []byte
}

func (m *newSessionTicketMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc5077#section-3.3
	ticketLen := len(m.ticket)
	length := 2 + 4 + ticketLen
	x = make([]byte, 4+length)
	x[0] = typeNewSessionTicket
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[8] = uint8(ticketLen >> 8)
	x[9] = uint8(ticketLen)
	copy(x[10:], m.ticket)

	m.raw = x

	return
}

func (m *newSessionTicketMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 10 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	ticketLen := int(data[8])<<8 + int(data[9])
	if len(data)-10 != ticketLen {
		return false
	}

	m.ticket = data[10:]

	return true
}

type v2ClientHelloMsg struct {
	raw          []byte
	vers         uint16
	cipherSuites []uint16
	sessionId    []byte
	challenge    []byte
}

func (m *v2ClientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 1 + 2 + 2 + 2 + 2 + len(m.cipherSuites)*3 + len(m.sessionId) + len(m.challenge)

	x := make([]byte, length)
	x[0] = 1
	x[1] = uint8(m.vers >> 8)
	x[2] = uint8(m.vers)
	x[3] = uint8((len(m.cipherSuites) * 3) >> 8)
	x[4] = uint8(len(m.cipherSuites) * 3)
	x[5] = uint8(len(m.sessionId) >> 8)
	x[6] = uint8(len(m.sessionId))
	x[7] = uint8(len(m.challenge) >> 8)
	x[8] = uint8(len(m.challenge))
	y := x[9:]
	for i, spec := range m.cipherSuites {
		y[i*3] = 0
		y[i*3+1] = uint8(spec >> 8)
		y[i*3+2] = uint8(spec)
	}
	y = y[len(m.cipherSuites)*3:]
	copy(y, m.sessionId)
	y = y[len(m.sessionId):]
	copy(y, m.challenge)

	m.raw = x

	return x
}

type helloVerifyRequestMsg struct {
	raw    []byte
	vers   uint16
	cookie []byte
}

func (m *helloVerifyRequestMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 1 + len(m.cookie)

	x := make([]byte, 4+length)
	x[0] = typeHelloVerifyRequest
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	vers := versionToWire(m.vers, true)
	x[4] = uint8(vers >> 8)
	x[5] = uint8(vers)
	x[6] = uint8(len(m.cookie))
	copy(x[7:7+len(m.cookie)], m.cookie)

	return x
}

func (m *helloVerifyRequestMsg) unmarshal(data []byte) bool {
	if len(data) < 4+2+1 {
		return false
	}
	m.raw = data
	m.vers = wireToVersion(uint16(data[4])<<8|uint16(data[5]), true)
	cookieLen := int(data[6])
	if cookieLen > 32 || len(data) != 7+cookieLen {
		return false
	}
	m.cookie = data[7 : 7+cookieLen]

	return true
}

type channelIDMsg struct {
	raw       []byte
	channelID []byte
}

func (m *channelIDMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 2 + len(m.channelID)

	x := make([]byte, 4+length)
	x[0] = typeChannelID
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(extensionChannelID >> 8)
	x[5] = uint8(extensionChannelID & 0xff)
	x[6] = uint8(len(m.channelID) >> 8)
	x[7] = uint8(len(m.channelID) & 0xff)
	copy(x[8:], m.channelID)

	return x
}

func (m *channelIDMsg) unmarshal(data []byte) bool {
	if len(data) != 4+2+2+128 {
		return false
	}
	m.raw = data
	if (uint16(data[4])<<8)|uint16(data[5]) != extensionChannelID {
		return false
	}
	if int(data[6])<<8|int(data[7]) != 128 {
		return false
	}
	m.channelID = data[4+2+2:]

	return true
}

type helloRequestMsg struct {
}

func (*helloRequestMsg) marshal() []byte {
	return []byte{typeHelloRequest, 0, 0, 0}
}

func (*helloRequestMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

func eqUint16s(x, y []uint16) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqCurveIDs(x, y []CurveID) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqStrings(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqByteSlices(x, y [][]byte) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if !bytes.Equal(v, y[i]) {
			return false
		}
	}
	return true
}

func eqSignatureAlgorithms(x, y []signatureAlgorithm) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		v2 := y[i]
		if v != v2 {
			return false
		}
	}
	return true
}
