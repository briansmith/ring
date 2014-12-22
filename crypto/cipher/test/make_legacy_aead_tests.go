package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	_ "crypto/md5"
	"crypto/rc4"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

var bulkCipher *string = flag.String("cipher", "", "The bulk cipher to use")
var mac *string = flag.String("mac", "", "The hash function to use in the MAC")
var implicitIV *bool = flag.Bool("implicit-iv", false, "If true, generate tests for a cipher using a pre-TLS-1.0 implicit IV")
var ssl3 *bool = flag.Bool("ssl3", false, "If true, use the SSLv3 MAC and padding rather than TLS")

// rc4Stream produces a deterministic stream of pseudorandom bytes. This is to
// make this script idempotent.
type rc4Stream struct {
	cipher *rc4.Cipher
}

func newRc4Stream(seed string) (*rc4Stream, error) {
	cipher, err := rc4.NewCipher([]byte(seed))
	if err != nil {
		return nil, err
	}
	return &rc4Stream{cipher}, nil
}

func (rs *rc4Stream) fillBytes(p []byte) {
	for i := range p {
		p[i] = 0
	}
	rs.cipher.XORKeyStream(p, p)
}

func getHash(name string) (crypto.Hash, bool) {
	switch name {
	case "md5":
		return crypto.MD5, true
	case "sha1":
		return crypto.SHA1, true
	case "sha256":
		return crypto.SHA256, true
	case "sha384":
		return crypto.SHA384, true
	default:
		return 0, false
	}
}

func getKeySize(name string) int {
	switch name {
	case "rc4":
		return 16
	case "aes128":
		return 16
	case "aes256":
		return 32
	case "3des":
		return 24
	default:
		return 0
	}
}

func newBlockCipher(name string, key []byte) (cipher.Block, error) {
	switch name {
	case "aes128":
		return aes.NewCipher(key)
	case "aes256":
		return aes.NewCipher(key)
	case "3des":
		return des.NewTripleDESCipher(key)
	default:
		return nil, fmt.Errorf("unknown cipher '%s'", name)
	}
}

var ssl30Pad1 = [48]byte{0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}

var ssl30Pad2 = [48]byte{0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}

func ssl30MAC(hash crypto.Hash, key, input, ad []byte) []byte {
	padLength := 48
	if hash.Size() == 20 {
		padLength = 40
	}

	h := hash.New()
	h.Write(key)
	h.Write(ssl30Pad1[:padLength])
	h.Write(ad)
	h.Write(input)
	digestBuf := h.Sum(nil)

	h.Reset()
	h.Write(key)
	h.Write(ssl30Pad2[:padLength])
	h.Write(digestBuf)
	return h.Sum(digestBuf[:0])
}

type testCase struct {
	digest     []byte
	key        []byte
	nonce      []byte
	input      []byte
	ad         []byte
	ciphertext []byte
	tag        []byte
}

func makeTestCase(length int) (*testCase, error) {
	rand, err := newRc4Stream("input stream")
	if err != nil {
		return nil, err
	}

	input := make([]byte, length)
	rand.fillBytes(input)

	var adFull []byte
	if *ssl3 {
		adFull = make([]byte, 11)
	} else {
		adFull = make([]byte, 13)
	}
	ad := adFull[:len(adFull)-2]
	rand.fillBytes(ad)
	adFull[len(adFull)-2] = uint8(length >> 8)
	adFull[len(adFull)-1] = uint8(length & 0xff)

	hash, ok := getHash(*mac)
	if !ok {
		return nil, fmt.Errorf("unknown hash function '%s'", *mac)
	}

	macKey := make([]byte, hash.Size())
	rand.fillBytes(macKey)

	var digest []byte
	if *ssl3 {
		if hash != crypto.SHA1 && hash != crypto.MD5 {
			return nil, fmt.Errorf("invalid hash for SSLv3: '%s'", *mac)
		}
		digest = ssl30MAC(hash, macKey, input, adFull)
	} else {
		h := hmac.New(hash.New, macKey)
		h.Write(adFull)
		h.Write(input)
		digest = h.Sum(nil)
	}

	size := getKeySize(*bulkCipher)
	if size == 0 {
		return nil, fmt.Errorf("unknown cipher '%s'", *bulkCipher)
	}
	encKey := make([]byte, size)
	rand.fillBytes(encKey)

	var fixedIV []byte
	var nonce []byte
	var sealed []byte
	if *bulkCipher == "rc4" {
		if *implicitIV {
			return nil, fmt.Errorf("implicit IV enabled on a stream cipher")
		}

		stream, err := rc4.NewCipher(encKey)
		if err != nil {
			return nil, err
		}

		sealed = make([]byte, 0, len(input)+len(digest))
		sealed = append(sealed, input...)
		sealed = append(sealed, digest...)
		stream.XORKeyStream(sealed, sealed)
	} else {
		block, err := newBlockCipher(*bulkCipher, encKey)
		if err != nil {
			return nil, err
		}

		iv := make([]byte, block.BlockSize())
		rand.fillBytes(iv)
		if *implicitIV || *ssl3 {
			fixedIV = iv
		} else {
			nonce = iv
		}

		cbc := cipher.NewCBCEncrypter(block, iv)

		sealed = make([]byte, 0, len(input)+len(digest)+cbc.BlockSize())
		sealed = append(sealed, input...)
		sealed = append(sealed, digest...)
		paddingLen := cbc.BlockSize() - (len(sealed) % cbc.BlockSize())
		// TODO(davidben): Add tests for non-minimal padding (SSL3
		// forbids, TLS allows) and arbitrary padding bytes (SSL3
		// allows, TLS forbids).
		if *ssl3 {
			sealed = append(sealed, make([]byte, paddingLen-1)...)
			sealed = append(sealed, byte(paddingLen-1))
		} else {
			pad := make([]byte, paddingLen)
			for i := range pad {
				pad[i] = byte(paddingLen - 1)
			}
			sealed = append(sealed, pad...)
		}
		cbc.CryptBlocks(sealed, sealed)
	}

	key := make([]byte, 0, len(macKey)+len(encKey)+len(fixedIV))
	key = append(key, macKey...)
	key = append(key, encKey...)
	key = append(key, fixedIV...)
	t := &testCase{
		digest:     digest,
		key:        key,
		nonce:      nonce,
		input:      input,
		ad:         ad,
		ciphertext: sealed[:len(sealed)-hash.Size()],
		tag:        sealed[len(sealed)-hash.Size():],
	}
	return t, nil
}

func main() {
	flag.Parse()

	commandLine := fmt.Sprintf("go run make_legacy_aead_tests.go -cipher %s -mac %s", *bulkCipher, *mac)
	if *implicitIV {
		commandLine += " -implicit-iv"
	}
	if *ssl3 {
		commandLine += " -ssl3"
	}
	fmt.Printf("# Generated by\n")
	fmt.Printf("#   %s\n", commandLine)
	fmt.Printf("#\n")
	fmt.Printf("# Note: aead_test's input format splits the ciphertext and tag positions of the sealed\n")
	fmt.Printf("# input. But these legacy AEADs are MAC-then-encrypt and may include padding, so this\n")
	fmt.Printf("# split isn't meaningful. The unencrypted MAC is included in the 'DIGEST' tag above\n")
	fmt.Printf("# each test case.\n")
	fmt.Printf("\n")

	// Generate long enough of input to cover a non-zero num_starting_blocks
	// value in the constant-time CBC logic.
	for l := 0; l < 500; l += 5 {
		t, err := makeTestCase(l)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		fmt.Printf("# DIGEST: %s\n", hex.EncodeToString(t.digest))
		fmt.Printf("KEY: %s\n", hex.EncodeToString(t.key))
		fmt.Printf("NONCE: %s\n", hex.EncodeToString(t.nonce))
		fmt.Printf("IN: %s\n", hex.EncodeToString(t.input))
		fmt.Printf("AD: %s\n", hex.EncodeToString(t.ad))
		fmt.Printf("CT: %s\n", hex.EncodeToString(t.ciphertext))
		fmt.Printf("TAG: %s\n", hex.EncodeToString(t.tag))
		fmt.Printf("\n")
	}
}
