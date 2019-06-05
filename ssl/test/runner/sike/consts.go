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

// I keep it bool in order to be able to apply logical NOT
type KeyVariant uint

// Representation of an element of the base field F_p.
//
// No particular meaning is assigned to the representation -- it could represent
// an element in Montgomery form, or not.  Tracking the meaning of the field
// element is left to higher types.
type Fp [FP_WORDS]uint64

// Represents an intermediate product of two elements of the base field F_p.
type FpX2 [2 * FP_WORDS]uint64

// Represents an element of the extended field Fp^2 = Fp(x+i)
type Fp2 struct {
	A Fp
	B Fp
}

type DomainParams struct {
	// P, Q and R=P-Q base points
	Affine_P, Affine_Q, Affine_R Fp2
	// Size of a compuatation strategy for x-torsion group
	IsogenyStrategy []uint32
	// Max size of secret key for x-torsion group
	SecretBitLen uint
	// Max size of secret key for x-torsion group
	SecretByteLen uint
}

type SidhParams struct {
	Id uint8
	// Bytelen of P
	Bytelen int
	// The public key size, in bytes.
	PublicKeySize int
	// The shared secret size, in bytes.
	SharedSecretSize int
	// 2- and 3-torsion group parameter definitions
	A, B DomainParams
	// Precomputed identity element in the Fp2 in Montgomery domain
	OneFp2 Fp2
	// Precomputed 1/2 in the Fp2 in Montgomery domain
	HalfFp2 Fp2
	// Length of SIKE secret message. Must be one of {24,32,40},
	// depending on size of prime field used (see [SIKE], 1.4 and 5.1)
	MsgLen int
	// Length of SIKE ephemeral KEM key (see [SIKE], 1.4 and 5.1)
	KemSize int
}

// Stores curve projective parameters equivalent to A/C. Meaning of the
// values depends on the context. When working with isogenies over
// subgroup that are powers of:
// * three then  (A:C) ~ (A+2C:A-2C)
// * four then   (A:C) ~ (A+2C:  4C)
// See Appendix A of SIKE for more details
type CurveCoefficientsEquiv struct {
	A Fp2
	C Fp2
}

// A point on the projective line P^1(F_{p^2}).
//
// This represents a point on the Kummer line of a Montgomery curve.  The
// curve is specified by a ProjectiveCurveParameters struct.
type ProjectivePoint struct {
	X Fp2
	Z Fp2
}

// Base type for public and private key. Used mainly to carry domain
// parameters.
type key struct {
	// Domain parameters of the algorithm to be used with a key
	params *SidhParams
	// Flag indicates whether corresponds to 2-, 3-torsion group or SIKE
	keyVariant KeyVariant
}

// Defines operations on private key
type PrivateKey struct {
	key
	// Secret key
	Scalar []byte
	// Used only by KEM
	S []byte
}

// Defines operations on public key
type PublicKey struct {
	key
	affine_xP   Fp2
	affine_xQ   Fp2
	affine_xQmP Fp2
}

// A point on the projective line P^1(F_{p^2}).
//
// This is used to work projectively with the curve coefficients.
type ProjectiveCurveParameters struct {
	A Fp2
	C Fp2
}

const (
	// First 2 bits identify SIDH variant third bit indicates
	// whether key is a SIKE variant (set) or SIDH (not set)

	// 001 - SIDH: corresponds to 2-torsion group
	KeyVariant_SIDH_A KeyVariant = 1 << 0
	// 010 - SIDH: corresponds to 3-torsion group
	KeyVariant_SIDH_B = 1 << 1
	// 110 - SIKE
	KeyVariant_SIKE = 1<<2 | KeyVariant_SIDH_B
	// Number of uint64 limbs used to store field element
	FP_WORDS = 8
)

// Used internally by this package
// -------------------------------

var p503 = Fp{
	0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xABFFFFFFFFFFFFFF,
	0x13085BDA2211E7A0, 0x1B9BF6C87B7E7DAF, 0x6045C6BDDA77A4D0, 0x004066F541811E1E,
}

// 2*503
var p503x2 = Fp{
	0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x57FFFFFFFFFFFFFF,
	0x2610B7B44423CF41, 0x3737ED90F6FCFB5E, 0xC08B8D7BB4EF49A0, 0x0080CDEA83023C3C,
}

// p503 + 1
var p503p1 = Fp{
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xAC00000000000000,
	0x13085BDA2211E7A0, 0x1B9BF6C87B7E7DAF, 0x6045C6BDDA77A4D0, 0x004066F541811E1E,
}

// R^2=(2^512)^2 mod p
var p503R2 = Fp{
	0x5289A0CF641D011F, 0x9B88257189FED2B9, 0xA3B365D58DC8F17A, 0x5BC57AB6EFF168EC,
	0x9E51998BD84D4423, 0xBF8999CBAC3B5695, 0x46E9127BCE14CDB6, 0x003F6CFCE8B81771,
}

// p503 + 1 left-shifted by 8, assuming little endianness
var p503p1s8 = Fp{
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x085BDA2211E7A0AC, 0x9BF6C87B7E7DAF13, 0x45C6BDDA77A4D01B, 0x4066F541811E1E60,
}

// 1*R mod p
var P503_OneFp2 = Fp2{
	A: Fp{
		0x00000000000003F9, 0x0000000000000000, 0x0000000000000000, 0xB400000000000000,
		0x63CB1A6EA6DED2B4, 0x51689D8D667EB37D, 0x8ACD77C71AB24142, 0x0026FBAEC60F5953},
}

// 1/2 * R mod p
var P503_HalfFp2 = Fp2{
	A: Fp{
		0x00000000000001FC, 0x0000000000000000, 0x0000000000000000, 0xB000000000000000,
		0x3B69BB2464785D2A, 0x36824A2AF0FE9896, 0xF5899F427A94F309, 0x0033B15203C83BB8},
}

var Params SidhParams

func init() {
	Params = SidhParams{
		// SIDH public key byte size.
		PublicKeySize: 378,
		// SIDH shared secret byte size.
		SharedSecretSize: 126,
		A: DomainParams{
			// The x-coordinate of PA
			Affine_P: Fp2{
				A: Fp{
					0xE7EF4AA786D855AF, 0xED5758F03EB34D3B, 0x09AE172535A86AA9, 0x237B9CC07D622723,
					0xE3A284CBA4E7932D, 0x27481D9176C5E63F, 0x6A323FF55C6E71BF, 0x002ECC31A6FB8773,
				},
				B: Fp{
					0x64D02E4E90A620B8, 0xDAB8128537D4B9F1, 0x4BADF77B8A228F98, 0x0F5DBDF9D1FB7D1B,
					0xBEC4DB288E1A0DCC, 0xE76A8665E80675DB, 0x6D6F252E12929463, 0x003188BD1463FACC,
				},
			},
			// The x-coordinate of QA
			Affine_Q: Fp2{
				A: Fp{
					0xB79D41025DE85D56, 0x0B867DA9DF169686, 0x740E5368021C827D, 0x20615D72157BF25C,
					0xFF1590013C9B9F5B, 0xC884DCADE8C16CEA, 0xEBD05E53BF724E01, 0x0032FEF8FDA5748C,
				},
				B: Fp{
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
				},
			},
			// The x-coordinate of RA = PA-QA
			Affine_R: Fp2{
				A: Fp{
					0x12E2E849AA0A8006, 0x41CF47008635A1E8, 0x9CD720A70798AED7, 0x42A820B42FCF04CF,
					0x7BF9BAD32AAE88B1, 0xF619127A54090BBE, 0x1CB10D8F56408EAA, 0x001D6B54C3C0EDEB,
				},
				B: Fp{
					0x34DB54931CBAAC36, 0x420A18CB8DD5F0C4, 0x32008C1A48C0F44D, 0x3B3BA772B1CFD44D,
					0xA74B058FDAF13515, 0x095FC9CA7EEC17B4, 0x448E829D28F120F8, 0x00261EC3ED16A489,
				},
			},
			// Max size of secret key for 2-torsion group, corresponds to 2^e2 - 1
			SecretBitLen: 250,
			// SecretBitLen in bytes.
			SecretByteLen: uint((250 + 7) / 8),
			// 2-torsion group computation strategy
			IsogenyStrategy: []uint32{
				0x3D, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x10, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01,
				0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x1D, 0x10, 0x08, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x0D, 0x08,
				0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x05, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01},
		},
		B: DomainParams{
			// The x-coordinate of PB
			Affine_P: Fp2{
				A: Fp{
					0x7EDE37F4FA0BC727, 0xF7F8EC5C8598941C, 0xD15519B516B5F5C8, 0xF6D5AC9B87A36282,
					0x7B19F105B30E952E, 0x13BD8B2025B4EBEE, 0x7B96D27F4EC579A2, 0x00140850CAB7E5DE,
				},
				B: Fp{
					0x7764909DAE7B7B2D, 0x578ABB16284911AB, 0x76E2BFD146A6BF4D, 0x4824044B23AA02F0,
					0x1105048912A321F3, 0xB8A2E482CF0F10C1, 0x42FF7D0BE2152085, 0x0018E599C5223352,
				},
			},
			// The x-coordinate of QB
			Affine_Q: Fp2{
				A: Fp{
					0x4256C520FB388820, 0x744FD7C3BAAF0A13, 0x4B6A2DDDB12CBCB8, 0xE46826E27F427DF8,
					0xFE4A663CD505A61B, 0xD6B3A1BAF025C695, 0x7C3BB62B8FCC00BD, 0x003AFDDE4A35746C,
				},
				B: Fp{
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
				},
			},
			// The x-coordinate of RB = PB - QB
			Affine_R: Fp2{
				A: Fp{
					0x75601CD1E6C0DFCB, 0x1A9007239B58F93E, 0xC1F1BE80C62107AC, 0x7F513B898F29FF08,
					0xEA0BEDFF43E1F7B2, 0x2C6D94018CBAE6D0, 0x3A430D31BCD84672, 0x000D26892ECCFE83,
				},
				B: Fp{
					0x1119D62AEA3007A1, 0xE3702AA4E04BAE1B, 0x9AB96F7D59F990E7, 0xF58440E8B43319C0,
					0xAF8134BEE1489775, 0xE7F7774E905192AA, 0xF54AE09308E98039, 0x001EF7A041A86112,
				},
			},
			// Size of secret key for 3-torsion group, corresponds to log_2(3^e3) - 1.
			SecretBitLen: 252,
			// SecretBitLen in bytes.
			SecretByteLen: uint((252 + 7) / 8),
			// 3-torsion group computation strategy
			IsogenyStrategy: []uint32{
				0x47, 0x26, 0x15, 0x0D, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x05, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02,
				0x01, 0x01, 0x01, 0x09, 0x05, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x01, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x11, 0x09, 0x05, 0x03, 0x02,
				0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02,
				0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x21, 0x11, 0x09, 0x05, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x04,
				0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x10, 0x08, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01},
		},
		OneFp2:  P503_OneFp2,
		HalfFp2: P503_HalfFp2,
		MsgLen:  24,
		// SIKEp503 provides 128 bit of classical security ([SIKE], 5.1)
		KemSize: 16,
		// ceil(503+7/8)
		Bytelen: 63,
	}
}
