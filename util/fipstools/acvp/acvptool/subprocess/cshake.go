// Copyright (c) 2025, Google Inc.
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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// The following structures reflect the JSON of ACVP XOF cSHAKE tests. See
// https://pages.nist.gov/ACVP/draft-celi-acvp-xof.html#name-test-vectors

type cShakeTestVectorSet struct {
	Groups []cShakeTestGroup `json:"testGroups"`
}

type cShakeTestGroup struct {
	ID                  uint64 `json:"tgId"`
	Type                string `json:"testType"`
	HexCustomization    bool   `json:"hexCustomization"`
	MaxOutLenBits       uint32 `json:"maxOutLen"`
	MinOutLenBits       uint32 `json:"minOutLen"`
	OutLenIncrementBits uint32 `json:"outLenIncrement"`
	Tests               []struct {
		ID               uint64 `json:"tcId"`
		MsgHex           string `json:"msg"`
		BitLength        uint64 `json:"len"`
		FunctionName     string `json:"functionName"`
		Customization    string `json:"customization"`
		CustomizationHex string `json:"customizationHex"`
		OutLenBits       uint32 `json:"outLen"`
	} `json:"tests"`
}

type cShakeTestGroupResponse struct {
	ID    uint64               `json:"tgId"`
	Tests []cShakeTestResponse `json:"tests"`
}

type cShakeTestResponse struct {
	ID         uint64            `json:"tcId"`
	DigestHex  string            `json:"md,omitempty"`
	OutLenBits uint32            `json:"outLen,omitempty"`
	MCTResults []cShakeMCTResult `json:"resultsArray,omitempty"`
}

type cShakeMCTResult struct {
	DigestHex  string `json:"md"`
	OutLenBits uint32 `json:"outLen,omitempty"`
}

type cShake struct {
	algo string
}

func (h *cShake) Process(vectorSet []byte, m Transactable) (any, error) {
	var parsed cShakeTestVectorSet
	if err := json.Unmarshal(vectorSet, &parsed); err != nil {
		return nil, err
	}

	// See
	// https://pages.nist.gov/ACVP/draft-celi-acvp-xof.html#name-test-types
	// for details about the tests.
	var ret []cShakeTestGroupResponse
	for _, group := range parsed.Groups {
		group := group
		response := cShakeTestGroupResponse{
			ID: group.ID,
		}

		if group.HexCustomization {
			return nil, fmt.Errorf("test group %d has unsupported hex customization", group.ID)
		}

		for _, test := range group.Tests {
			test := test

			if test.CustomizationHex != "" {
				return nil, fmt.Errorf("test case %d/%d has unsupported hex customization", group.ID, test.ID)
			}

			if uint64(len(test.MsgHex))*4 != test.BitLength {
				return nil, fmt.Errorf("test case %d/%d contains hex message of length %d but specifies a bit length of %d", group.ID, test.ID, len(test.MsgHex), test.BitLength)
			}
			msg, err := hex.DecodeString(test.MsgHex)
			if err != nil {
				return nil, fmt.Errorf("failed to decode hex in test case %d/%d: %s", group.ID, test.ID, err)
			}

			if test.OutLenBits%8 != 0 {
				return nil, fmt.Errorf("test case %d/%d has bit length %d - fractional bytes not supported", group.ID, test.ID, test.OutLenBits)
			}

			switch group.Type {
			case "AFT":
				args := [][]byte{msg, uint32le(test.OutLenBits / 8), []byte(test.FunctionName), []byte(test.Customization)}
				m.TransactAsync(h.algo, 1, args, func(result [][]byte) error {
					response.Tests = append(response.Tests, cShakeTestResponse{
						ID:         test.ID,
						DigestHex:  hex.EncodeToString(result[0]),
						OutLenBits: test.OutLenBits,
					})
					return nil
				})
			case "MCT":
				testResponse := cShakeTestResponse{ID: test.ID}

				if group.MinOutLenBits%8 != 0 {
					return nil, fmt.Errorf("MCT test group %d has min output length %d - fractional bytes not supported", group.ID, group.MinOutLenBits)
				}
				if group.MaxOutLenBits%8 != 0 {
					return nil, fmt.Errorf("MCT test group %d has max output length %d - fractional bytes not supported", group.ID, group.MaxOutLenBits)
				}
				if group.OutLenIncrementBits%8 != 0 {
					return nil, fmt.Errorf("MCT test group %d has output length increment %d - fractional bytes not supported", group.ID, group.OutLenIncrementBits)
				}

				minOutLenBytes := uint32le(group.MinOutLenBits / 8)
				maxOutLenBytes := uint32le(group.MaxOutLenBits / 8)
				outputLenBytes := uint32le(group.MaxOutLenBits / 8)
				incrementBytes := uint32le(group.OutLenIncrementBits / 8)
				var mctCustomization []byte

				for i := 0; i < 100; i++ {
					args := [][]byte{msg, minOutLenBytes, maxOutLenBytes, outputLenBytes, incrementBytes, mctCustomization}
					result, err := m.Transact(h.algo+"/MCT", 3, args...)
					if err != nil {
						panic(h.algo + " mct operation failed: " + err.Error())
					}

					msg = result[0]
					outputLenBytes = uint32le(binary.LittleEndian.Uint32(result[1]))
					mctCustomization = result[2]

					mctResult := cShakeMCTResult{
						DigestHex:  hex.EncodeToString(msg),
						OutLenBits: uint32(len(msg) * 8),
					}
					testResponse.MCTResults = append(testResponse.MCTResults, mctResult)
				}

				response.Tests = append(response.Tests, testResponse)
			default:
				return nil, fmt.Errorf("test group %d has unknown type %q", group.ID, group.Type)
			}
		}

		m.Barrier(func() {
			ret = append(ret, response)
		})
	}

	if err := m.Flush(); err != nil {
		return nil, err
	}

	return ret, nil
}
