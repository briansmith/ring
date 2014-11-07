// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"errors"
	"net"
)

type packetAdaptor struct {
	net.Conn
}

// newPacketAdaptor wraps a reliable streaming net.Conn into a
// reliable packet-based net.Conn. Every packet is encoded with a
// 32-bit length prefix as a framing layer.
func newPacketAdaptor(conn net.Conn) net.Conn {
	return &packetAdaptor{conn}
}

func (p *packetAdaptor) Read(b []byte) (int, error) {
	var length uint32
	if err := binary.Read(p.Conn, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	out := make([]byte, length)
	n, err := p.Conn.Read(out)
	if err != nil {
		return 0, err
	}
	if n != int(length) {
		return 0, errors.New("internal error: length mismatch!")
	}
	return copy(b, out), nil
}

func (p *packetAdaptor) Write(b []byte) (int, error) {
	length := uint32(len(b))
	if err := binary.Write(p.Conn, binary.BigEndian, length); err != nil {
		return 0, err
	}
	n, err := p.Conn.Write(b)
	if err != nil {
		return 0, err
	}
	if n != len(b) {
		return 0, errors.New("internal error: length mismatch!")
	}
	return len(b), nil
}

type replayAdaptor struct {
	net.Conn
	prevWrite []byte
}

// newReplayAdaptor wraps a packeted net.Conn. It transforms it into
// one which, after writing a packet, always replays the previous
// write.
func newReplayAdaptor(conn net.Conn) net.Conn {
	return &replayAdaptor{Conn: conn}
}

func (r *replayAdaptor) Write(b []byte) (int, error) {
	n, err := r.Conn.Write(b)

	// Replay the previous packet and save the current one to
	// replay next.
	if r.prevWrite != nil {
		r.Conn.Write(r.prevWrite)
	}
	r.prevWrite = append(r.prevWrite[:0], b...)

	return n, err
}
