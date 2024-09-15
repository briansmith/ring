// Copyright (c) 2024, Google Inc.
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
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func step(desc string, f func(*stepPrinter) error) error {
	fmt.Printf("%s...", desc)
	if *pipe {
		fmt.Printf("\n")
	} else {
		fmt.Printf(" ")
	}
	s := stepPrinter{lastPercent: -1}
	err := f(&s)
	s.erasePercent()
	if err != nil {
		fmt.Printf("ERROR\n")
	} else {
		fmt.Printf("OK\n")
	}
	return err
}

type stepPrinter struct {
	lastPercent     int
	percentLen      int
	progress, total int
}

func (s *stepPrinter) erasePercent() {
	if !*pipe && s.percentLen > 0 {
		var erase strings.Builder
		for i := 0; i < s.percentLen; i++ {
			erase.WriteString("\b \b")
		}
		fmt.Printf("%s", erase.String())
		s.percentLen = 0
	}
}

func (s *stepPrinter) setTotal(total int) {
	s.progress = 0
	s.total = total
	s.printPercent()
}

func (s *stepPrinter) addProgress(delta int) {
	s.progress += delta
	s.printPercent()
}

func (s *stepPrinter) printPercent() {
	if s.total <= 0 {
		return
	}

	percent := 100
	if s.progress < s.total {
		percent = 100 * s.progress / s.total
	}
	if *pipe {
		percent -= percent % 10
	}
	if percent == s.lastPercent {
		return
	}

	s.erasePercent()

	s.lastPercent = percent
	str := fmt.Sprintf("%d%%", percent)
	s.percentLen = len(str)
	fmt.Printf("%s", str)
	if *pipe {
		fmt.Printf("\n")
	}
}

func (s *stepPrinter) progressWriter(total int) io.Writer {
	s.setTotal(total)
	return &progressWriter{step: s}
}

func (s *stepPrinter) httpBodyWithProgress(r *http.Response) io.Reader {
	// This does not always give any progress. It seems GitHub will sometimes
	// provide a Content-Length header and sometimes not, for the same URL.
	return io.TeeReader(r.Body, s.progressWriter(int(r.ContentLength)))
}

type progressWriter struct {
	step *stepPrinter
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.step.addProgress(len(b))
	return len(b), nil
}
