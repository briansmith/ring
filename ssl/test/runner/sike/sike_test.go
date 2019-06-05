// Copyright (c) 2019, Cloudflare Inc.
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

package sike

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

var tdata = struct {
	name     string
	PrB_sidh string
	PkB_sidh string
	PkB_sike string
	PrB_sike string
	PrA_sike string
	PkA_sike string
}{
	name:     "P-503",
	PkB_sike: "68460C22466E95864CFEA7B5D9077E768FF4F9ED69AE56D7CF3F236FB06B31020EEE34B5B572CEA5DDF20B531966AA8F5F3ACC0C6D1CE04EEDC30FD1F1233E2D96FE60C6D638FC646EAF2E2246F1AEC96859CE874A1F029A78F9C978CD6B22114A0D5AB20101191FD923E80C76908B1498B9D0200065CCA09159A0C65A1E346CC6470314FE78388DAA89DD08EC67DBE63C1F606674ACC49EBF9FDBB2B898B3CE733113AA6F942DB401A76D629CE6EE6C0FDAF4CFB1A5E366DB66C17B3923A1B7FB26A3FF25B9018869C674D3DEF4AF269901D686FE4647F9D2CDB2CEB3AFA305B27C885F037ED167F595066C21E7DD467D8332B934A5102DA5F13332DFA356B82156A0BB2E7E91C6B85B7D1E381BC9E3F0FC4DB9C36016D9ECEC415D7E977E9AC29910D934BA2FE4EE49D3B387607A4E1AFABF495FB86A77194626589E802FF5167C7A25C542C1EAD25A6E0AA931D94F2F9AFD3DBDF222E651F729A90E77B20974905F1E65E041CE6C95AAB3E1F22D332E0A5DE9C5DB3D9C7A38",
	PrB_sike: "80FC55DA74DEFE3113487B80841E678AF9ED4E0599CF07353A4AB93971C090A0" +
		"A9402C9DC98AC6DC8F5FDE5E970AE22BA48A400EFC72851C",
	PrB_sidh: "A885A8B889520A6DBAD9FB33365E5B77FDED629440A16A533F259A510F63A822",
	PrA_sike: "B0AD510708F4ABCF3E0D97DC2F2FF112D9D2AAE49D97FFD1E4267F21C6E71C03",
	PkA_sike: "A6BADBA04518A924B20046B59AC197DCDF0EA48014C9E228C4994CCA432F360E" +
		"2D527AFB06CA7C96EE5CEE19BAD53BF9218A3961CAD7EC092BD8D9EBB22A3D51" +
		"33008895A3F1F6A023F91E0FE06A00A622FD6335DAC107F8EC4283DC2632F080" +
		"4E64B390DAD8A2572F1947C67FDF4F8787D140CE2C6B24E752DA9A195040EDFA" +
		"C27333FAE97DBDEB41DA9EEB2DB067AE7DA8C58C0EF57AEFC18A3D6BD0576FF2" +
		"F1CFCAEC50C958331BF631F3D2E769790C7B6DF282B74BBC02998AD10F291D47" +
		"C5A762FF84253D3B3278BDF20C8D4D4AA317BE401B884E26A1F02C7308AADB68" +
		"20EBDB0D339F5A63346F3B40CACED72F544DAF51566C6E807D0E6E1E38514342" +
		"432661DC9564DA07548570E256688CD9E8060D8775F95D501886D958588CACA0" +
		"9F2D2AE1913F996E76AF63E31A179A7A7D2A46EDA03B2BCCF9020A5AA15F9A28" +
		"9340B33F3AE7F97360D45F8AE1B9DD48779A57E8C45B50A02C00349CD1C58C55" +
		"1D68BC2A75EAFED944E8C599C288037181E997471352E24C952B",
	PkB_sidh: "244AF1F367C2C33912750A98497CC8214BC195BD52BD76513D32ACE4B75E31F0" +
		"281755C265F5565C74E3C04182B9C244071859C8588CC7F09547CEFF8F7705D2" +
		"60CE87D6BFF914EE7DBE4B9AF051CA420062EEBDF043AF58184495026949B068" +
		"98A47046BFAE8DF3B447746184AF550553BB5D266D6E1967ACA33CAC5F399F90" +
		"360D70867F2C71EF6F94FF915C7DA8BC9549FB7656E691DAEFC93CF56876E482" +
		"CA2F8BE2D6CDCC374C31AD8833CABE997CC92305F38497BEC4DFD1821B004FEC" +
		"E16448F9A24F965EFE409A8939EEA671633D9FFCF961283E59B8834BDF7EDDB3" +
		"05D6275B61DA6692325432A0BAA074FC7C1F51E76208AB193A57520D40A76334" +
		"EE5712BDC3E1EFB6103966F2329EDFF63082C4DFCDF6BE1C5A048630B81871B8" +
		"83B735748A8FD4E2D9530C272163AB18105B10015CA7456202FE1C9B92CEB167" +
		"5EAE1132E582C88E47ED87B363D45F05BEA714D5E9933D7AF4071CBB5D49008F" +
		"3E3DAD7DFF935EE509D5DE561842B678CCEB133D62E270E9AC3E",
}

/* -------------------------------------------------------------------------
   Helpers
   -------------------------------------------------------------------------*/
// Fail if err !=nil. Display msg as an error message
func checkErr(t testing.TB, err error, msg string) {
	if err != nil {
		t.Error(msg)
	}
}

// Utility used for running same test with all registered prime fields
type MultiIdTestingFunc func(testing.TB)

// Converts string to private key
func convToPrv(s string, v KeyVariant) *PrivateKey {
	key := NewPrivateKey(v)
	hex, e := hex.DecodeString(s)
	if e != nil {
		panic("non-hex number provided")
	}
	e = key.Import(hex)
	if e != nil {
		panic("Can't import private key")
	}
	return key
}

// Converts string to public key
func convToPub(s string, v KeyVariant) *PublicKey {
	key := NewPublicKey(v)
	hex, e := hex.DecodeString(s)
	if e != nil {
		panic("non-hex number provided")
	}
	e = key.Import(hex)
	if e != nil {
		panic("Can't import public key")
	}
	return key
}

/* -------------------------------------------------------------------------
   Unit tests
   -------------------------------------------------------------------------*/
func TestKeygen(t *testing.T) {
	alicePrivate := convToPrv(tdata.PrA_sike, KeyVariant_SIDH_A)
	bobPrivate := convToPrv(tdata.PrB_sidh, KeyVariant_SIDH_B)
	expPubA := convToPub(tdata.PkA_sike, KeyVariant_SIDH_A)
	expPubB := convToPub(tdata.PkB_sidh, KeyVariant_SIDH_B)

	pubA := alicePrivate.GeneratePublicKey()
	pubB := bobPrivate.GeneratePublicKey()

	if !bytes.Equal(pubA.Export(), expPubA.Export()) {
		t.Fatalf("unexpected value of public key A")
	}
	if !bytes.Equal(pubB.Export(), expPubB.Export()) {
		t.Fatalf("unexpected value of public key B")
	}
}

func TestImportExport(t *testing.T) {
	var err error
	a := NewPublicKey(KeyVariant_SIDH_A)
	b := NewPublicKey(KeyVariant_SIDH_B)

	// Import keys
	a_hex, err := hex.DecodeString(tdata.PkA_sike)
	checkErr(t, err, "invalid hex-number provided")

	err = a.Import(a_hex)
	checkErr(t, err, "import failed")

	b_hex, err := hex.DecodeString(tdata.PkB_sike)
	checkErr(t, err, "invalid hex-number provided")

	err = b.Import(b_hex)
	checkErr(t, err, "import failed")

	// Export and check if same
	if !bytes.Equal(b.Export(), b_hex) || !bytes.Equal(a.Export(), a_hex) {
		t.Fatalf("export/import failed")
	}

	if (len(b.Export()) != b.Size()) || (len(a.Export()) != a.Size()) {
		t.Fatalf("wrong size of exported keys")
	}
}

func testPrivateKeyBelowMax(t testing.TB) {
	for variant, keySz := range map[KeyVariant]*DomainParams{
		KeyVariant_SIDH_A: &Params.A,
		KeyVariant_SIDH_B: &Params.B} {

		func(v KeyVariant, dp *DomainParams) {
			var blen = int(dp.SecretByteLen)
			var prv = NewPrivateKey(v)

			// Calculate either (2^e2 - 1) or (2^s - 1); where s=ceil(log_2(3^e3)))
			maxSecertVal := big.NewInt(int64(dp.SecretBitLen))
			maxSecertVal.Exp(big.NewInt(int64(2)), maxSecertVal, nil)
			maxSecertVal.Sub(maxSecertVal, big.NewInt(1))

			// Do same test 1000 times
			for i := 0; i < 1000; i++ {
				err := prv.Generate(rand.Reader)
				checkErr(t, err, "Private key generation")

				// Convert to big-endian, as that's what expected by (*Int)SetBytes()
				secretBytes := prv.Export()
				for i := 0; i < int(blen/2); i++ {
					tmp := secretBytes[i] ^ secretBytes[blen-i-1]
					secretBytes[i] = tmp ^ secretBytes[i]
					secretBytes[blen-i-1] = tmp ^ secretBytes[blen-i-1]
				}
				prvBig := new(big.Int).SetBytes(secretBytes)
				// Check if generated key is bigger than acceptable
				if prvBig.Cmp(maxSecertVal) == 1 {
					t.Error("Generated private key is wrong")
				}
			}
		}(variant, keySz)
	}
}

func testKeyAgreement(t *testing.T, pkA, prA, pkB, prB string) {
	var e error

	// KeyPairs
	alicePublic := convToPub(pkA, KeyVariant_SIDH_A)
	bobPublic := convToPub(pkB, KeyVariant_SIDH_B)
	alicePrivate := convToPrv(prA, KeyVariant_SIDH_A)
	bobPrivate := convToPrv(prB, KeyVariant_SIDH_B)

	// Do actual test
	s1, e := DeriveSecret(bobPrivate, alicePublic)
	checkErr(t, e, "derivation s1")
	s2, e := DeriveSecret(alicePrivate, bobPublic)
	checkErr(t, e, "derivation s1")

	if !bytes.Equal(s1[:], s2[:]) {
		t.Fatalf("two shared keys: %d, %d do not match", s1, s2)
	}

	// Negative case
	dec, e := hex.DecodeString(tdata.PkA_sike)
	if e != nil {
		t.FailNow()
	}
	dec[0] = ^dec[0]
	e = alicePublic.Import(dec)
	if e != nil {
		t.FailNow()
	}

	s1, e = DeriveSecret(bobPrivate, alicePublic)
	checkErr(t, e, "derivation of s1 failed")
	s2, e = DeriveSecret(alicePrivate, bobPublic)
	checkErr(t, e, "derivation of s2 failed")

	if bytes.Equal(s1[:], s2[:]) {
		t.Fatalf("The two shared keys: %d, %d match", s1, s2)
	}
}

func TestDerivationRoundTrip(t *testing.T) {
	var err error

	prvA := NewPrivateKey(KeyVariant_SIDH_A)
	prvB := NewPrivateKey(KeyVariant_SIDH_B)

	// Generate private keys
	err = prvA.Generate(rand.Reader)
	checkErr(t, err, "key generation failed")
	err = prvB.Generate(rand.Reader)
	checkErr(t, err, "key generation failed")

	// Generate public keys
	pubA := prvA.GeneratePublicKey()
	pubB := prvB.GeneratePublicKey()

	// Derive shared secret
	s1, err := DeriveSecret(prvB, pubA)
	checkErr(t, err, "")

	s2, err := DeriveSecret(prvA, pubB)
	checkErr(t, err, "")

	if !bytes.Equal(s1[:], s2[:]) {
		t.Fatalf("Two shared keys: \n%X, \n%X do not match", s1, s2)
	}
}

// Encrypt, Decrypt, check if input/output plaintext is the same
func testPKERoundTrip(t testing.TB, id uint8) {
	// Message to be encrypted
	var msg = make([]byte, Params.MsgLen)
	for i, _ := range msg {
		msg[i] = byte(i)
	}

	// Import keys
	pkB := NewPublicKey(KeyVariant_SIKE)
	skB := NewPrivateKey(KeyVariant_SIKE)
	pk_hex, err := hex.DecodeString(tdata.PkB_sike)
	if err != nil {
		t.Fatal(err)
	}
	sk_hex, err := hex.DecodeString(tdata.PrB_sike)
	if err != nil {
		t.Fatal(err)
	}
	if pkB.Import(pk_hex) != nil || skB.Import(sk_hex) != nil {
		t.Error("Import")
	}

	ct, err := Encrypt(rand.Reader, pkB, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(skB, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt[:], msg[:]) {
		t.Errorf("Decryption failed \n got : %X\n exp : %X", pt, msg)
	}
}

// Generate key and check if can encrypt
func TestPKEKeyGeneration(t *testing.T) {
	// Message to be encrypted
	var msg = make([]byte, Params.MsgLen)
	var err error
	for i, _ := range msg {
		msg[i] = byte(i)
	}

	sk := NewPrivateKey(KeyVariant_SIKE)
	err = sk.Generate(rand.Reader)
	checkErr(t, err, "PEK key generation")
	pk := sk.GeneratePublicKey()

	// Try to encrypt
	ct, err := Encrypt(rand.Reader, pk, msg[:])
	checkErr(t, err, "PEK encryption")
	pt, err := Decrypt(sk, ct)
	checkErr(t, err, "PEK key decryption")

	if !bytes.Equal(pt[:], msg[:]) {
		t.Fatalf("Decryption failed \n got : %X\n exp : %X", pt, msg)
	}
}

func TestNegativePKE(t *testing.T) {
	var msg [40]byte
	var err error

	// Generate key
	sk := NewPrivateKey(KeyVariant_SIKE)
	err = sk.Generate(rand.Reader)
	checkErr(t, err, "key generation")

	pk := sk.GeneratePublicKey()

	// bytelen(msg) - 1
	ct, err := Encrypt(rand.Reader, pk, msg[:Params.KemSize+8-1])
	if err == nil {
		t.Fatal("Error hasn't been returned")
	}
	if ct != nil {
		t.Fatal("Ciphertext must be nil")
	}

	// KemSize - 1
	pt, err := Decrypt(sk, msg[:Params.KemSize+8-1])
	if err == nil {
		t.Fatal("Error hasn't been returned")
	}
	if pt != nil {
		t.Fatal("Ciphertext must be nil")
	}
}

func testKEMRoundTrip(t *testing.T, pkB, skB []byte) {
	// Import keys
	pk := NewPublicKey(KeyVariant_SIKE)
	sk := NewPrivateKey(KeyVariant_SIKE)
	if pk.Import(pkB) != nil || sk.Import(skB) != nil {
		t.Error("Import failed")
	}

	ct, ss_e, err := Encapsulate(rand.Reader, pk)
	if err != nil {
		t.Error("Encapsulate failed")
	}

	ss_d, err := Decapsulate(sk, pk, ct)
	if err != nil {
		t.Error("Decapsulate failed")
	}
	if !bytes.Equal(ss_e, ss_d) {
		t.Error("Shared secrets from decapsulation and encapsulation differ")
	}
}

func TestKEMRoundTrip(t *testing.T) {
	pk, err := hex.DecodeString(tdata.PkB_sike)
	checkErr(t, err, "public key B not a number")
	sk, err := hex.DecodeString(tdata.PrB_sike)
	checkErr(t, err, "private key B not a number")
	testKEMRoundTrip(t, pk, sk)
}

func TestKEMKeyGeneration(t *testing.T) {
	// Generate key
	sk := NewPrivateKey(KeyVariant_SIKE)
	checkErr(t, sk.Generate(rand.Reader), "error: key generation")
	pk := sk.GeneratePublicKey()

	// calculated shared secret
	ct, ss_e, err := Encapsulate(rand.Reader, pk)
	checkErr(t, err, "encapsulation failed")
	ss_d, err := Decapsulate(sk, pk, ct)
	checkErr(t, err, "decapsulation failed")

	if !bytes.Equal(ss_e, ss_d) {
		t.Fatalf("KEM failed \n encapsulated: %X\n decapsulated: %X", ss_d, ss_e)
	}
}

func TestNegativeKEM(t *testing.T) {
	sk := NewPrivateKey(KeyVariant_SIKE)
	checkErr(t, sk.Generate(rand.Reader), "error: key generation")
	pk := sk.GeneratePublicKey()

	ct, ss_e, err := Encapsulate(rand.Reader, pk)
	checkErr(t, err, "pre-requisite for a test failed")

	ct[0] = ct[0] - 1
	ss_d, err := Decapsulate(sk, pk, ct)
	checkErr(t, err, "decapsulation returns error when invalid ciphertext provided")

	if bytes.Equal(ss_e, ss_d) {
		// no idea how this could ever happen, but it would be very bad
		t.Error("critical error")
	}

	// Try encapsulating with SIDH key
	pkSidh := NewPublicKey(KeyVariant_SIDH_B)
	prSidh := NewPrivateKey(KeyVariant_SIDH_B)
	_, _, err = Encapsulate(rand.Reader, pkSidh)
	if err == nil {
		t.Error("encapsulation accepts SIDH public key")
	}
	// Try decapsulating with SIDH key
	_, err = Decapsulate(prSidh, pk, ct)
	if err == nil {
		t.Error("decapsulation accepts SIDH private key key")
	}
}

// In case invalid ciphertext is provided, SIKE's decapsulation must
// return same (but unpredictable) result for a given key.
func TestNegativeKEMSameWrongResult(t *testing.T) {
	sk := NewPrivateKey(KeyVariant_SIKE)
	checkErr(t, sk.Generate(rand.Reader), "error: key generation")
	pk := sk.GeneratePublicKey()

	ct, encSs, err := Encapsulate(rand.Reader, pk)
	checkErr(t, err, "pre-requisite for a test failed")

	// make ciphertext wrong
	ct[0] = ct[0] - 1
	decSs1, err := Decapsulate(sk, pk, ct)
	checkErr(t, err, "pre-requisite for a test failed")

	// second decapsulation must be done with same, but imported private key
	expSk := sk.Export()

	// creat new private key
	sk = NewPrivateKey(KeyVariant_SIKE)
	err = sk.Import(expSk)
	checkErr(t, err, "import failed")

	// try decapsulating again. ss2 must be same as ss1 and different than
	// original plaintext
	decSs2, err := Decapsulate(sk, pk, ct)
	checkErr(t, err, "pre-requisite for a test failed")

	if !bytes.Equal(decSs1, decSs2) {
		t.Error("decapsulation is insecure")
	}

	if bytes.Equal(encSs, decSs1) || bytes.Equal(encSs, decSs2) {
		// this test requires that decapsulation returns wrong result
		t.Errorf("test implementation error")
	}
}

func readAndCheckLine(r *bufio.Reader) []byte {
	// Read next line from buffer
	line, isPrefix, err := r.ReadLine()
	if err != nil || isPrefix {
		panic("Wrong format of input file")
	}

	// Function expects that line is in format "KEY = HEX_VALUE". Get
	// value, which should be a hex string
	hexst := strings.Split(string(line), "=")[1]
	hexst = strings.TrimSpace(hexst)
	// Convert value to byte string
	ret, err := hex.DecodeString(hexst)
	if err != nil {
		panic("Wrong format of input file")
	}
	return ret
}

func testKeygenSIKE(pk, sk []byte, id uint8) bool {
	// Import provided private key
	var prvKey = NewPrivateKey(KeyVariant_SIKE)
	if prvKey.Import(sk) != nil {
		panic("sike test: can't load KAT")
	}

	// Generate public key
	pubKey := prvKey.GeneratePublicKey()
	return bytes.Equal(pubKey.Export(), pk)
}

func testDecapsulation(pk, sk, ct, ssExpected []byte, id uint8) bool {
	var pubKey = NewPublicKey(KeyVariant_SIKE)
	var prvKey = NewPrivateKey(KeyVariant_SIKE)
	if pubKey.Import(pk) != nil || prvKey.Import(sk) != nil {
		panic("sike test: can't load KAT")
	}

	ssGot, err := Decapsulate(prvKey, pubKey, ct)
	if err != nil {
		panic("sike test: can't perform degcapsulation KAT")
	}

	return bytes.Equal(ssGot, ssExpected)
}

func TestKeyAgreement(t *testing.T) {
	testKeyAgreement(t, tdata.PkA_sike, tdata.PrA_sike, tdata.PkB_sidh, tdata.PrB_sidh)
}

// Same values as in sike_test.cc
func TestDecapsulation(t *testing.T) {

	var sk = [56]byte{
		0xDB, 0xAF, 0x2C, 0x89, 0xCA, 0x5A, 0xD4, 0x9D, 0x4F, 0x13,
		0x40, 0xDF, 0x2D, 0xB1, 0x5F, 0x4C, 0x91, 0xA7, 0x1F, 0x0B,
		0x29, 0x15, 0x01, 0x59, 0xBC, 0x5F, 0x0B, 0x4A, 0x03, 0x27,
		0x6F, 0x18}

	var pk = []byte{
		0x07, 0xAA, 0x51, 0x45, 0x3E, 0x1F, 0x53, 0x2A, 0x0A, 0x05,
		0x46, 0xF6, 0x54, 0x7F, 0x5D, 0x56, 0xD6, 0x76, 0xD3, 0xEA,
		0x4B, 0x6B, 0x01, 0x9B, 0x11, 0x72, 0x6F, 0x75, 0xEA, 0x34,
		0x3C, 0x28, 0x2C, 0x36, 0xFD, 0x77, 0xDA, 0xBE, 0xB6, 0x20,
		0x18, 0xC1, 0x93, 0x98, 0x18, 0x86, 0x30, 0x2F, 0x2E, 0xD2,
		0x00, 0x61, 0xFF, 0xAE, 0x78, 0xAE, 0xFB, 0x6F, 0x32, 0xAC,
		0x06, 0xBF, 0x35, 0xF6, 0xF7, 0x5B, 0x98, 0x26, 0x95, 0xC2,
		0xD8, 0xD6, 0x1C, 0x0E, 0x47, 0xDA, 0x76, 0xCE, 0xB5, 0xF1,
		0x19, 0xCC, 0x01, 0xE1, 0x17, 0xA9, 0x62, 0xF7, 0x82, 0x6C,
		0x25, 0x51, 0x25, 0xAE, 0xFE, 0xE3, 0xE2, 0xE1, 0x35, 0xAE,
		0x2E, 0x8F, 0x38, 0xE0, 0x7C, 0x74, 0x3C, 0x1D, 0x39, 0x91,
		0x1B, 0xC7, 0x9F, 0x8E, 0x33, 0x4E, 0x84, 0x19, 0xB8, 0xD9,
		0xC2, 0x71, 0x35, 0x02, 0x47, 0x3E, 0x79, 0xEF, 0x47, 0xE1,
		0xD8, 0x21, 0x96, 0x1F, 0x11, 0x59, 0x39, 0x34, 0x76, 0xEF,
		0x3E, 0xB7, 0x4E, 0xFB, 0x7C, 0x55, 0xA1, 0x85, 0xAA, 0xAB,
		0xAD, 0xF0, 0x09, 0xCB, 0xD1, 0xE3, 0x7C, 0x4F, 0x5D, 0x2D,
		0xE1, 0x13, 0xF0, 0x71, 0xD9, 0xE5, 0xF6, 0xAF, 0x7F, 0xC1,
		0x27, 0x95, 0x8D, 0x52, 0xD5, 0x96, 0x42, 0x38, 0x41, 0xF7,
		0x24, 0x3F, 0x3A, 0xB5, 0x7E, 0x11, 0xE4, 0xF9, 0x33, 0xEE,
		0x4D, 0xBE, 0x74, 0x48, 0xF9, 0x98, 0x04, 0x01, 0x16, 0xEB,
		0xA9, 0x0D, 0x61, 0xC6, 0xFD, 0x4C, 0xCF, 0x98, 0x84, 0x4A,
		0x94, 0xAC, 0x69, 0x2C, 0x02, 0x8B, 0xE3, 0xD1, 0x41, 0x0D,
		0xF2, 0x2D, 0x46, 0x1F, 0x57, 0x1C, 0x77, 0x86, 0x18, 0xE3,
		0x63, 0xDE, 0xF3, 0xE3, 0x02, 0x30, 0x54, 0x73, 0xAE, 0xC2,
		0x32, 0xA2, 0xCE, 0xEB, 0xCF, 0x81, 0x46, 0x54, 0x5C, 0xF4,
		0x5D, 0x2A, 0x03, 0x5D, 0x9C, 0xAE, 0xE0, 0x60, 0x03, 0x80,
		0x11, 0x30, 0xA5, 0xAA, 0xD1, 0x75, 0x67, 0xE0, 0x1C, 0x2B,
		0x6B, 0x5D, 0x83, 0xDE, 0x92, 0x9B, 0x0E, 0xD7, 0x11, 0x0F,
		0x00, 0xC4, 0x59, 0xE4, 0x81, 0x04, 0x3B, 0xEE, 0x5C, 0x04,
		0xD1, 0x0E, 0xD0, 0x67, 0xF5, 0xCC, 0xAA, 0x72, 0x73, 0xEA,
		0xC4, 0x76, 0x99, 0x3B, 0x4C, 0x90, 0x2F, 0xCB, 0xD8, 0x0A,
		0x5B, 0xEC, 0x0E, 0x0E, 0x1F, 0x59, 0xEA, 0x14, 0x8D, 0x34,
		0x53, 0x65, 0x4C, 0x1A, 0x59, 0xA8, 0x95, 0x66, 0x60, 0xBB,
		0xC4, 0xCC, 0x32, 0xA9, 0x8D, 0x2A, 0xAA, 0x14, 0x6F, 0x0F,
		0x81, 0x4D, 0x32, 0x02, 0xFD, 0x33, 0x58, 0x42, 0xCF, 0xF3,
		0x67, 0xD0, 0x9F, 0x0B, 0xB1, 0xCC, 0x18, 0xA5, 0xC4, 0x19,
		0xB6, 0x00, 0xED, 0xFA, 0x32, 0x1A, 0x5F, 0x67, 0xC8, 0xC3,
		0xEB, 0x0D, 0xB5, 0x9A, 0x36, 0x47, 0x82, 0x00,
	}

	var ct = []byte{
		0xE6, 0xB7, 0xE5, 0x7B, 0xA9, 0x19, 0xD1, 0x2C, 0xB8, 0x5C,
		0x7B, 0x66, 0x74, 0xB0, 0x71, 0xA1, 0xFF, 0x71, 0x7F, 0x4B,
		0xB5, 0xA6, 0xAF, 0x48, 0x32, 0x52, 0xD5, 0x82, 0xEE, 0x8A,
		0xBB, 0x08, 0x1E, 0xF6, 0xAC, 0x91, 0xA2, 0xCB, 0x6B, 0x6A,
		0x09, 0x2B, 0xD9, 0xC6, 0x27, 0xD6, 0x3A, 0x6B, 0x8D, 0xFC,
		0xB8, 0x90, 0x8F, 0x72, 0xB3, 0xFA, 0x7D, 0x34, 0x7A, 0xC4,
		0x7E, 0xE3, 0x30, 0xC5, 0xA0, 0xFE, 0x3D, 0x43, 0x14, 0x4E,
		0x3A, 0x14, 0x76, 0x3E, 0xFB, 0xDF, 0xE3, 0xA8, 0xE3, 0x5E,
		0x38, 0xF2, 0xE0, 0x39, 0x67, 0x60, 0xFD, 0xFB, 0xB4, 0x19,
		0xCD, 0xE1, 0x93, 0xA2, 0x06, 0xCC, 0x65, 0xCD, 0x6E, 0xC8,
		0xB4, 0x5E, 0x41, 0x4B, 0x6C, 0xA5, 0xF4, 0xE4, 0x9D, 0x52,
		0x8C, 0x25, 0x60, 0xDD, 0x3D, 0xA9, 0x7F, 0xF2, 0x88, 0xC1,
		0x0C, 0xEE, 0x97, 0xE0, 0xE7, 0x3B, 0xB7, 0xD3, 0x6F, 0x28,
		0x79, 0x2F, 0x50, 0xB2, 0x4F, 0x74, 0x3A, 0x0C, 0x88, 0x27,
		0x98, 0x3A, 0x27, 0xD3, 0x26, 0x83, 0x59, 0x49, 0x81, 0x5B,
		0x0D, 0xA7, 0x0C, 0x4F, 0xEF, 0xFB, 0x1E, 0xAF, 0xE9, 0xD2,
		0x1C, 0x10, 0x25, 0xEC, 0x9E, 0xFA, 0x57, 0x36, 0xAA, 0x3F,
		0xC1, 0xA3, 0x2C, 0xE9, 0xB5, 0xC9, 0xED, 0x72, 0x51, 0x4C,
		0x02, 0xB4, 0x7B, 0xB3, 0xED, 0x9F, 0x45, 0x03, 0x34, 0xAC,
		0x9A, 0x9E, 0x62, 0x5F, 0x82, 0x7A, 0x77, 0x34, 0xF9, 0x21,
		0x94, 0xD2, 0x38, 0x3D, 0x05, 0xF0, 0x8A, 0x60, 0x1C, 0xB7,
		0x1D, 0xF5, 0xB7, 0x53, 0x77, 0xD3, 0x9D, 0x3D, 0x70, 0x6A,
		0xCB, 0x18, 0x20, 0x6B, 0x29, 0x17, 0x3A, 0x6D, 0xA1, 0xB2,
		0x64, 0xDB, 0x6C, 0xE6, 0x1A, 0x95, 0xA7, 0xF4, 0x1A, 0x78,
		0x1D, 0xA2, 0x40, 0x15, 0x41, 0x59, 0xDD, 0xEE, 0x23, 0x57,
		0xCE, 0x36, 0x0D, 0x55, 0xBD, 0xB8, 0xFD, 0x0F, 0x35, 0xBD,
		0x5B, 0x92, 0xD6, 0x1C, 0x84, 0x8C, 0x32, 0x64, 0xA6, 0x5C,
		0x45, 0x18, 0x07, 0x6B, 0xF9, 0xA9, 0x43, 0x9A, 0x83, 0xCD,
		0xB5, 0xB3, 0xD9, 0x17, 0x99, 0x2C, 0x2A, 0x8B, 0xE0, 0x8E,
		0xAF, 0xA6, 0x4C, 0x95, 0xBB, 0x70, 0x60, 0x1A, 0x3A, 0x97,
		0xAA, 0x2F, 0x3D, 0x22, 0x83, 0xB7, 0x4F, 0x59, 0xED, 0x3F,
		0x4E, 0xF4, 0x19, 0xC6, 0x25, 0x0B, 0x0A, 0x5E, 0x21, 0xB9,
		0x91, 0xB8, 0x19, 0x84, 0x48, 0x78, 0xCE, 0x27, 0xBF, 0x41,
		0x89, 0xF6, 0x30, 0xFD, 0x6B, 0xD9, 0xB8, 0x1D, 0x72, 0x8A,
		0x56, 0xCC, 0x2F, 0x82, 0xE4, 0x46, 0x4D, 0x75, 0xD8, 0x92,
		0xE6, 0x9C, 0xCC, 0xD2, 0xCD, 0x35, 0xE4, 0xFC, 0x2A, 0x85,
		0x6B, 0xA9, 0xB2, 0x27, 0xC9, 0xA1, 0xFF, 0xB3, 0x96, 0x3E,
		0x59, 0xF6, 0x4C, 0x66, 0x56, 0x2E, 0xF5, 0x1B, 0x97, 0x32,
		0xB0, 0x71, 0x5A, 0x9C, 0x50, 0x4B, 0x6F, 0xC4, 0xCA, 0x94,
		0x75, 0x37, 0x46, 0x10, 0x12, 0x2F, 0x4F, 0xA3, 0x82, 0xCD,
		0xBD, 0x7C,
	}
	var ss_exp = []byte{
		0x74, 0x3D, 0x25, 0x36, 0x00, 0x24, 0x63, 0x1A, 0x39, 0x1A,
		0xB4, 0xAD, 0x01, 0x17, 0x78, 0xE9}

	var prvObj = NewPrivateKey(KeyVariant_SIKE)
	var pubObj = NewPublicKey(KeyVariant_SIKE)

	if pubObj.Import(pk) != nil || prvObj.Import(sk[:]) != nil {
		t.Error("Can't import one of the keys")
	}

	res, _ := Decapsulate(prvObj, pubObj, ct)
	if !bytes.Equal(ss_exp, res) {
		t.Error("Wrong decapsulation result")
	}
}

/* -------------------------------------------------------------------------
   Benchmarking
   -------------------------------------------------------------------------*/

func BenchmarkSidhKeyAgreementP503(b *testing.B) {
	// KeyPairs
	alicePublic := convToPub(tdata.PkA_sike, KeyVariant_SIDH_A)
	alicePrivate := convToPrv(tdata.PrA_sike, KeyVariant_SIDH_A)
	bobPublic := convToPub(tdata.PkB_sidh, KeyVariant_SIDH_B)
	bobPrivate := convToPrv(tdata.PrB_sidh, KeyVariant_SIDH_B)

	for i := 0; i < b.N; i++ {
		// Derive shared secret
		DeriveSecret(bobPrivate, alicePublic)
		DeriveSecret(alicePrivate, bobPublic)
	}
}

func BenchmarkAliceKeyGenPrvP503(b *testing.B) {
	prv := NewPrivateKey(KeyVariant_SIDH_A)
	for n := 0; n < b.N; n++ {
		prv.Generate(rand.Reader)
	}
}

func BenchmarkBobKeyGenPrvP503(b *testing.B) {
	prv := NewPrivateKey(KeyVariant_SIDH_B)
	for n := 0; n < b.N; n++ {
		prv.Generate(rand.Reader)
	}
}

func BenchmarkAliceKeyGenPubP503(b *testing.B) {
	prv := NewPrivateKey(KeyVariant_SIDH_A)
	prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey()
	}
}

func BenchmarkBobKeyGenPubP503(b *testing.B) {
	prv := NewPrivateKey(KeyVariant_SIDH_B)
	prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey()
	}
}

func BenchmarkSharedSecretAliceP503(b *testing.B) {
	aPr := convToPrv(tdata.PrA_sike, KeyVariant_SIDH_A)
	bPk := convToPub(tdata.PkB_sike, KeyVariant_SIDH_B)
	for n := 0; n < b.N; n++ {
		DeriveSecret(aPr, bPk)
	}
}

func BenchmarkSharedSecretBobP503(b *testing.B) {
	// m_B = 3*randint(0,3^238)
	aPk := convToPub(tdata.PkA_sike, KeyVariant_SIDH_A)
	bPr := convToPrv(tdata.PrB_sidh, KeyVariant_SIDH_B)
	for n := 0; n < b.N; n++ {
		DeriveSecret(bPr, aPk)
	}
}
