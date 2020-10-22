// Copyright (c) 2020, Google Inc.
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

package subprocess

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// See https://usnistgov.github.io/ACVP/draft-celi-acvp-rsa.html#section-7.4
// although, at the time of writing, that spec doesn't match what the NIST demo
// server actually produces. This code matches the server.

type rsaTestVectorSet struct {
	Mode string `json:"mode"`
}

type rsaKeyGenTestVectorSet struct {
	Groups []rsaKeyGenGroup `json:"testGroups"`
}

type rsaKeyGenGroup struct {
	ID          uint64          `json:"tgId"`
	Type        string          `json:"testType"`
	ModulusBits uint32          `json:"modulo"`
	Tests       []rsaKeyGenTest `json:"tests"`
}

type rsaKeyGenTest struct {
	ID uint64 `json:"tcId"`
}

type rsaKeyGenTestGroupResponse struct {
	ID    uint64                  `json:"tgId"`
	Tests []rsaKeyGenTestResponse `json:"tests"`
}

type rsaKeyGenTestResponse struct {
	ID uint64 `json:"tcId"`
	E  string `json:"e"`
	P  string `json:"p"`
	Q  string `json:"q"`
	N  string `json:"n"`
	D  string `json:"d"`
}

func processKeyGen(vectorSet []byte, m Transactable) (interface{}, error) {
	var parsed rsaKeyGenTestVectorSet
	if err := json.Unmarshal(vectorSet, &parsed); err != nil {
		return nil, err
	}

	var ret []rsaKeyGenTestGroupResponse

	for _, group := range parsed.Groups {
		// GDT means "Generated data test", i.e. "please generate an RSA key".
		const expectedType = "GDT"
		if group.Type != expectedType {
			return nil, fmt.Errorf("RSA KeyGen test group has type %q, but only generation tests (%q) are supported", group.Type, expectedType)
		}

		response := rsaKeyGenTestGroupResponse{
			ID: group.ID,
		}

		for _, test := range group.Tests {
			results, err := m.Transact("RSA/keyGen", 5, uint32le(group.ModulusBits))
			if err != nil {
				return nil, err
			}

			response.Tests = append(response.Tests, rsaKeyGenTestResponse{
				ID: test.ID,
				E:  hex.EncodeToString(results[0]),
				P:  hex.EncodeToString(results[1]),
				Q:  hex.EncodeToString(results[2]),
				N:  hex.EncodeToString(results[3]),
				D:  hex.EncodeToString(results[4]),
			})
		}

		ret = append(ret, response)
	}

	return ret, nil
}

type rsa struct{}

func (*rsa) Process(vectorSet []byte, m Transactable) (interface{}, error) {
	var parsed rsaTestVectorSet
	if err := json.Unmarshal(vectorSet, &parsed); err != nil {
		return nil, err
	}

	switch parsed.Mode {
	case "keyGen":
		return processKeyGen(vectorSet, m)
	default:
		return nil, fmt.Errorf("Unknown RSA mode %q", parsed.Mode)
	}
}
