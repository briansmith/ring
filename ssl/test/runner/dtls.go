// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DTLS implementation.
//
// NOTE: This is a not even a remotely production-quality DTLS
// implementation. It is the bare minimum necessary to be able to
// achieve coverage on BoringSSL's implementation. Of note is that
// this implementation assumes the underlying net.PacketConn is not
// only reliable but also ordered. BoringSSL will be expected to deal
// with simulated loss, but there is no point in forcing the test
// driver to.

package main

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
)

func versionToWire(vers uint16, isDTLS bool) uint16 {
	if isDTLS {
		return ^(vers - 0x0201)
	}
	return vers
}

func wireToVersion(vers uint16, isDTLS bool) uint16 {
	if isDTLS {
		return ^vers + 0x0201
	}
	return vers
}

func (c *Conn) dtlsDoReadRecord(want recordType) (recordType, *block, error) {
	recordHeaderLen := dtlsRecordHeaderLen

	if c.rawInput == nil {
		c.rawInput = c.in.newBlock()
	}
	b := c.rawInput

	// Read a new packet only if the current one is empty.
	if len(b.data) == 0 {
		// Pick some absurdly large buffer size.
		b.resize(maxCiphertext + recordHeaderLen)
		n, err := c.conn.Read(c.rawInput.data)
		if err != nil {
			return 0, nil, err
		}
		c.rawInput.resize(n)
	}

	// Read out one record.
	//
	// A real DTLS implementation should be tolerant of errors,
	// but this is test code. We should not be tolerant of our
	// peer sending garbage.
	if len(b.data) < recordHeaderLen {
		return 0, nil, errors.New("dtls: failed to read record header")
	}
	typ := recordType(b.data[0])
	vers := wireToVersion(uint16(b.data[1])<<8|uint16(b.data[2]), c.isDTLS)
	if c.haveVers && vers != c.vers {
		c.sendAlert(alertProtocolVersion)
		return 0, nil, c.in.setErrorLocked(fmt.Errorf("dtls: received record with version %x when expecting version %x", vers, c.vers))
	}
	seq := b.data[3:11]
	// For test purposes, we assume a reliable channel. Require
	// that the explicit sequence number matches the incrementing
	// one we maintain. A real implementation would maintain a
	// replay window and such.
	if !bytes.Equal(seq, c.in.seq[:]) {
		c.sendAlert(alertIllegalParameter)
		return 0, nil, c.in.setErrorLocked(fmt.Errorf("dtls: bad sequence number"))
	}
	n := int(b.data[11])<<8 | int(b.data[12])
	if n > maxCiphertext || len(b.data) < recordHeaderLen+n {
		c.sendAlert(alertRecordOverflow)
		return 0, nil, c.in.setErrorLocked(fmt.Errorf("dtls: oversized record received with length %d", n))
	}

	// Process message.
	b, c.rawInput = c.in.splitBlock(b, recordHeaderLen+n)
	ok, off, err := c.in.decrypt(b)
	if !ok {
		c.in.setErrorLocked(c.sendAlert(err))
	}
	b.off = off
	return typ, b, nil
}

func (c *Conn) dtlsWriteRecord(typ recordType, data []byte) (n int, err error) {
	recordHeaderLen := dtlsRecordHeaderLen
	maxLen := c.config.Bugs.MaxHandshakeRecordLength
	if maxLen <= 0 {
		maxLen = 1024
	}

	b := c.out.newBlock()

	var header []byte
	if typ == recordTypeHandshake {
		// Handshake messages have to be modified to include
		// fragment offset and length and with the header
		// replicated. Save the header here.
		//
		// TODO(davidben): This assumes that data contains
		// exactly one handshake message. This is incompatible
		// with FragmentAcrossChangeCipherSpec. (Which is
		// unfortunate because OpenSSL's DTLS implementation
		// will probably accept such fragmentation and could
		// do with a fix + tests.)
		if len(data) < 4 {
			// This should not happen.
			panic(data)
		}
		header = data[:4]
		data = data[4:]
	}

	firstRun := true
	for firstRun || len(data) > 0 {
		firstRun = false
		m := len(data)
		var fragment []byte
		// Handshake messages get fragmented. Other records we
		// pass-through as is. DTLS should be a packet
		// interface.
		if typ == recordTypeHandshake {
			if m > maxLen {
				m = maxLen
			}

			// Standard handshake header.
			fragment = make([]byte, 0, 12+m)
			fragment = append(fragment, header...)
			// message_seq
			fragment = append(fragment, byte(c.sendHandshakeSeq>>8), byte(c.sendHandshakeSeq))
			// fragment_offset
			fragment = append(fragment, byte(n>>16), byte(n>>8), byte(n))
			// fragment_length
			fragment = append(fragment, byte(m>>16), byte(m>>8), byte(m))
			fragment = append(fragment, data[:m]...)
		} else {
			fragment = data[:m]
		}

		// Send the fragment.
		explicitIVLen := 0
		explicitIVIsSeq := false

		if cbc, ok := c.out.cipher.(cbcMode); ok {
			// Block cipher modes have an explicit IV.
			explicitIVLen = cbc.BlockSize()
		} else if _, ok := c.out.cipher.(cipher.AEAD); ok {
			explicitIVLen = 8
			// The AES-GCM construction in TLS has an
			// explicit nonce so that the nonce can be
			// random. However, the nonce is only 8 bytes
			// which is too small for a secure, random
			// nonce. Therefore we use the sequence number
			// as the nonce.
			explicitIVIsSeq = true
		} else if c.out.cipher != nil {
			panic("Unknown cipher")
		}
		b.resize(recordHeaderLen + explicitIVLen + len(fragment))
		b.data[0] = byte(typ)
		vers := c.vers
		if vers == 0 {
			// Some TLS servers fail if the record version is
			// greater than TLS 1.0 for the initial ClientHello.
			vers = VersionTLS10
		}
		vers = versionToWire(vers, c.isDTLS)
		b.data[1] = byte(vers >> 8)
		b.data[2] = byte(vers)
		// DTLS records include an explicit sequence number.
		copy(b.data[3:11], c.out.seq[0:])
		b.data[11] = byte(len(fragment) >> 8)
		b.data[12] = byte(len(fragment))
		if explicitIVLen > 0 {
			explicitIV := b.data[recordHeaderLen : recordHeaderLen+explicitIVLen]
			if explicitIVIsSeq {
				copy(explicitIV, c.out.seq[:])
			} else {
				if _, err = io.ReadFull(c.config.rand(), explicitIV); err != nil {
					break
				}
			}
		}
		copy(b.data[recordHeaderLen+explicitIVLen:], fragment)
		c.out.encrypt(b, explicitIVLen)

		// TODO(davidben): A real DTLS implementation needs to
		// retransmit handshake messages. For testing
		// purposes, we don't actually care.
		_, err = c.conn.Write(b.data)
		if err != nil {
			break
		}
		n += m
		data = data[m:]
	}
	c.out.freeBlock(b)

	// Increment the handshake sequence number for the next
	// handshake message.
	if typ == recordTypeHandshake {
		c.sendHandshakeSeq++
	}

	if typ == recordTypeChangeCipherSpec {
		err = c.out.changeCipherSpec(c.config)
		if err != nil {
			// Cannot call sendAlert directly,
			// because we already hold c.out.Mutex.
			c.tmp[0] = alertLevelError
			c.tmp[1] = byte(err.(alert))
			c.writeRecord(recordTypeAlert, c.tmp[0:2])
			return n, c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
		}
	}
	return
}

func (c *Conn) dtlsDoReadHandshake() ([]byte, error) {
	// Assemble a full handshake message.  For test purposes, this
	// implementation assumes fragments arrive in order. It may
	// need to be cleverer if we ever test BoringSSL's retransmit
	// behavior.
	for len(c.handMsg) < 4+c.handMsgLen {
		// Get a new handshake record if the previous has been
		// exhausted.
		if c.hand.Len() == 0 {
			if err := c.in.err; err != nil {
				return nil, err
			}
			if err := c.readRecord(recordTypeHandshake); err != nil {
				return nil, err
			}
		}

		// Read the next fragment. It must fit entirely within
		// the record.
		if c.hand.Len() < 12 {
			return nil, errors.New("dtls: bad handshake record")
		}
		header := c.hand.Next(12)
		fragN := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
		fragSeq := uint16(header[4])<<8 | uint16(header[5])
		fragOff := int(header[6])<<16 | int(header[7])<<8 | int(header[8])
		fragLen := int(header[9])<<16 | int(header[10])<<8 | int(header[11])

		if c.hand.Len() < fragLen {
			return nil, errors.New("dtls: fragment length too long")
		}
		fragment := c.hand.Next(fragLen)

		// Check it's a fragment for the right message.
		if fragSeq != c.recvHandshakeSeq {
			return nil, errors.New("dtls: bad handshake sequence number")
		}

		// Check that the length is consistent.
		if c.handMsg == nil {
			c.handMsgLen = fragN
			if c.handMsgLen > maxHandshake {
				return nil, c.in.setErrorLocked(c.sendAlert(alertInternalError))
			}
			// Start with the TLS handshake header,
			// without the DTLS bits.
			c.handMsg = append([]byte{}, header[:4]...)
		} else if fragN != c.handMsgLen {
			return nil, errors.New("dtls: bad handshake length")
		}

		// Add the fragment to the pending message.
		if 4+fragOff != len(c.handMsg) {
			return nil, errors.New("dtls: bad fragment offset")
		}
		if fragOff+fragLen > c.handMsgLen {
			return nil, errors.New("dtls: bad fragment length")
		}
		c.handMsg = append(c.handMsg, fragment...)
	}
	c.recvHandshakeSeq++
	ret := c.handMsg
	c.handMsg, c.handMsgLen = nil, 0
	return ret, nil
}

// DTLSServer returns a new DTLS server side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and must have
// at least one certificate.
func DTLSServer(conn net.Conn, config *Config) *Conn {
	c := &Conn{config: config, isDTLS: true, conn: conn}
	c.init()
	return c
}

// DTLSClient returns a new DTLS client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerHostname or
// InsecureSkipVerify in the config.
func DTLSClient(conn net.Conn, config *Config) *Conn {
	c := &Conn{config: config, isClient: true, isDTLS: true, conn: conn}
	c.init()
	return c
}
