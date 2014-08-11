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
