// Copyright (c) 2017, Google Inc.
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

// ar.go contains functions for parsing .a archive files.

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// the string which begins a proper archive
	arMagic = "!<arch>\n"

	// the magic numbers for individual file headers
	fileMagic = "`\n"

	headerSize = 60
)

// An ARHeader represents a single header in an ar archive.
type ARHeader struct {
	Name    string
	ModTime time.Time
	UID     int
	GID     int
	Mode    os.FileMode
	Size    int64
}

type slicer []byte

func (sp *slicer) next(n int) (b []byte) {
	s := *sp
	b, *sp = s[0:n], s[n:]
	return
}

// A Reader provides sequential access to the contents of an ar archive.
// The Next method advances to the next file in the archive (including
// the first), and then it can be treated as an io.Reader to access the
// file's data.
type AR struct {
	r   io.Reader
	err error
	nb  int64 // number of unread bytes for current file entry
	pad int   // amount of padding after current file entry
}

// NewReader returns a reader for the members of the provided ar archive.
func NewAR(r io.Reader) *AR {
	magiclen := len(arMagic)
	buf := make([]byte, magiclen)
	_, err := io.ReadFull(r, buf)
	if err != nil || arMagic != string(buf) {
		err = fmt.Errorf("ar: bad magic number %v in ar file header", buf)
	}
	return &AR{r: r, err: err}
}

// Next advances the reader to the next file in the archive.
func (ar *AR) Next() (*ARHeader, error) {
	var hdr *ARHeader
	if ar.err == nil {
		ar.skipUnread()
	}
	if ar.err == nil {
		hdr = ar.readHeader()
	}
	return hdr, ar.err
}

func (ar *AR) cvt(b []byte, base int) int64 {
	// Removing leading spaces
	for len(b) > 0 && b[0] == ' ' {
		b = b[1:]
	}
	// Removing trailing NULs and spaces.
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\x00') {
		b = b[:len(b)-1]
	}

	if len(b) == 0 {
		return 0
	}

	x, err := strconv.ParseUint(string(b), base, 64)
	if err != nil {
		ar.err = err
	}
	return int64(x)
}

// Skip any unused bytes in the existing file entry, as well as any alignment padding.
func (ar *AR) skipUnread() {
	nr := ar.nb + int64(ar.pad)
	ar.nb, ar.pad = 0, 0
	if sr, ok := ar.r.(io.Seeker); ok {
		if _, err := sr.Seek(nr, io.SeekCurrent); err == nil {
			return
		}
	}
	_, ar.err = io.CopyN(ioutil.Discard, ar.r, nr)
}

func (ar *AR) readHeader() *ARHeader {
	var n int
	header := make([]byte, headerSize)
	n, ar.err = io.ReadFull(ar.r, header)
	if ar.err == io.ErrUnexpectedEOF {
		ar.err = fmt.Errorf("ar: short header in ar archive; got %d bytes, want %d", n, headerSize)
	}
	if ar.err != nil {
		// io.EOF will get passed through
		return nil
	}

	hdr := new(ARHeader)
	s := slicer(header)

	hdr.Name = strings.TrimRight(string(s.next(16)), " ")
	hdr.Name = strings.TrimRight(hdr.Name, "/")
	hdr.ModTime = time.Unix(ar.cvt(s.next(12), 10), 0)
	hdr.UID = int(ar.cvt(s.next(6), 10))
	hdr.GID = int(ar.cvt(s.next(6), 10))
	hdr.Mode = os.FileMode(ar.cvt(s.next(8), 8))
	hdr.Size = ar.cvt(s.next(10), 10)
	magic := string(s.next(2))
	if magic != fileMagic {
		ar.err = fmt.Errorf("ar: bad magic number %v in ar member header", magic)
		return nil
	}

	ar.nb = int64(hdr.Size)
	// at most one pad byte just to be even
	ar.pad = int(ar.nb & 1)

	return hdr
}

// Read reads from the current entry in the ar archive.
// It returns 0, io.EOF when it reaches the end of that entry,
// until Next is called to advance to the next entry.
func (ar *AR) Read(b []byte) (n int, err error) {
	if ar.nb == 0 {
		// file consumed
		return 0, io.EOF
	}

	// trim read to the amount available
	if int64(len(b)) > ar.nb {
		b = b[0:ar.nb]
	}

	n, err = ar.r.Read(b)
	ar.nb -= int64(n)
	if err == io.EOF && ar.nb > 0 {
		// archive ended while more file contents expected
		err = io.ErrUnexpectedEOF
	}
	ar.err = err
	return
}
