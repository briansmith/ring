#include <stdint.h>
#include <immintrin.h>
#include <string.h>

typedef uint64_t fe4[4];
typedef uint8_t fiat_uint1;
typedef int8_t fiat_int1;

static __inline__ uint64_t fiat_value_barrier_u64(uint64_t a) {
  __asm__("" : "+r"(a) : /* no inputs */);
  return a;
}
static inline void fe4_mul(fe4 out, const fe4 x, const fe4 y) { fiat_curve25519_adx_mul(out, x, y); }
static inline void fe4_sq(fe4 out, const fe4 x) { fiat_curve25519_adx_square(out, x); }

/*
 * The function fiat_mulx_u64 is a multiplication, returning the full double-width result.
 *
 * Postconditions:
 *   out1 = (arg1 * arg2) mod 2^64
 *   out2 = ⌊arg1 * arg2 / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0xffffffffffffffff]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0xffffffffffffffff]
 */
static inline void fiat_mulx_u64(uint64_t* out1, uint64_t* out2, uint64_t arg1, uint64_t arg2) {
// NOTE: edited after generation
#if defined(_M_X64)
  unsigned long long t;
  *out1 = _umul128(arg1, arg2, &t);
  *out2 = t;
#elif defined(_M_ARM64)
  *out1 = arg1 * arg2;
  *out2 = __umulh(arg1, arg2);
#else
  unsigned __int128 t = (unsigned __int128)arg1 * arg2;
  *out1 = t;
  *out2 = (t >> 64);
#endif
}

/*
 * The function fiat_addcarryx_u64 is an addition with carry.
 *
 * Postconditions:
 *   out1 = (arg1 + arg2 + arg3) mod 2^64
 *   out2 = ⌊(arg1 + arg2 + arg3) / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0x1]
 */
static inline void fiat_addcarryx_u64(uint64_t* out1, fiat_uint1* out2, fiat_uint1 arg1, uint64_t arg2, uint64_t arg3) {
// NOTE: edited after generation
#if defined(__has_builtin)
#  if __has_builtin(__builtin_ia32_addcarryx_u64)
#    define addcarry64 __builtin_ia32_addcarryx_u64
#  endif
#endif
#if defined(addcarry64)
  long long unsigned int t;
  *out2 = addcarry64(arg1, arg2, arg3, &t);
  *out1 = t;
#elif defined(_M_X64)
  long long unsigned int t;
  *out2 = _addcarry_u64(arg1, arg2, arg3, out1);
  *out1 = t;
#else
  arg2 += arg1;
  arg1 = arg2 < arg1;
  uint64_t ret = arg2 + arg3;
  arg1 += ret < arg2;
  *out1 = ret;
  *out2 = arg1;
#endif
#undef addcarry64
}

/*
 * The function fiat_subborrowx_u64 is a subtraction with borrow.
 *
 * Postconditions:
 *   out1 = (-arg1 + arg2 + -arg3) mod 2^64
 *   out2 = -⌊(-arg1 + arg2 + -arg3) / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0x1]
 */
static inline void fiat_subborrowx_u64(uint64_t* out1, fiat_uint1* out2, fiat_uint1 arg1, uint64_t arg2, uint64_t arg3) {
#if defined(__has_builtin)
#  if __has_builtin(__builtin_ia32_subborrow_u64)
#    define subborrow64 __builtin_ia32_subborrow_u64
#  endif
#endif
#if defined(subborrow64)
  long long unsigned int t;
  *out2 = subborrow64(arg1, arg2, arg3, &t);
  *out1 = t;
#elif defined(_M_X64)
  long long unsigned int t;
  *out2 = _subborrow_u64(arg1, arg2, arg3, &t); // NOTE: edited after generation
  *out1 = t;
#else
  *out1 = arg2 - arg3 - arg1;
  *out2 = (arg2 < arg3) | ((arg2 == arg3) & arg1);
#endif
#undef subborrow64
}

/*
 * The function fiat_cmovznz_u64 is a single-word conditional move.
 *
 * Postconditions:
 *   out1 = (if arg1 = 0 then arg2 else arg3)
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 */
static inline void fiat_cmovznz_u64(uint64_t* out1, fiat_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  fiat_uint1 x1;
  uint64_t x2;
  uint64_t x3;
  x1 = (!(!arg1));
  x2 = ((fiat_int1)(0x0 - x1) & UINT64_C(0xffffffffffffffff));
  x3 = ((fiat_value_barrier_u64(x2) & arg3) | (fiat_value_barrier_u64((~x2)) & arg2));
  *out1 = x3;
}

/*
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
static void fe4_add(uint64_t out1[4], const uint64_t arg1[4], const uint64_t arg2[4]) {
  uint64_t x1;
  fiat_uint1 x2;
  uint64_t x3;
  fiat_uint1 x4;
  uint64_t x5;
  fiat_uint1 x6;
  uint64_t x7;
  fiat_uint1 x8;
  uint64_t x9;
  uint64_t x10;
  fiat_uint1 x11;
  uint64_t x12;
  fiat_uint1 x13;
  uint64_t x14;
  fiat_uint1 x15;
  uint64_t x16;
  fiat_uint1 x17;
  uint64_t x18;
  uint64_t x19;
  fiat_uint1 x20;
  fiat_addcarryx_u64(&x1, &x2, 0x0, (arg1[0]), (arg2[0]));
  fiat_addcarryx_u64(&x3, &x4, x2, (arg1[1]), (arg2[1]));
  fiat_addcarryx_u64(&x5, &x6, x4, (arg1[2]), (arg2[2]));
  fiat_addcarryx_u64(&x7, &x8, x6, (arg1[3]), (arg2[3]));
  fiat_cmovznz_u64(&x9, x8, 0x0, UINT8_C(0x26)); // NOTE: clang 14 for Zen 2 uses sbb, and
  fiat_addcarryx_u64(&x10, &x11, 0x0, x1, x9);
  fiat_addcarryx_u64(&x12, &x13, x11, x3, 0x0);
  fiat_addcarryx_u64(&x14, &x15, x13, x5, 0x0);
  fiat_addcarryx_u64(&x16, &x17, x15, x7, 0x0);
  fiat_cmovznz_u64(&x18, x17, 0x0, UINT8_C(0x26)); // NOTE: clang 14 for Zen 2 uses sbb, and
  fiat_addcarryx_u64(&x19, &x20, 0x0, x10, x18);
  out1[0] = x19;
  out1[1] = x12;
  out1[2] = x14;
  out1[3] = x16;
}

/*
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
static void fe4_sub(uint64_t out1[4], const uint64_t arg1[4], const uint64_t arg2[4]) {
  uint64_t x1;
  uint64_t x2;
  fiat_uint1 x3;
  uint64_t x4;
  uint64_t x5;
  fiat_uint1 x6;
  uint64_t x7;
  uint64_t x8;
  fiat_uint1 x9;
  uint64_t x10;
  uint64_t x11;
  fiat_uint1 x12;
  uint64_t x13;
  uint64_t x14;
  fiat_uint1 x15;
  uint64_t x16;
  fiat_uint1 x17;
  uint64_t x18;
  fiat_uint1 x19;
  uint64_t x20;
  fiat_uint1 x21;
  uint64_t x22;
  uint64_t x23;
  fiat_uint1 x24;
  x1 = (arg2[0]);
  fiat_subborrowx_u64(&x2, &x3, 0x0, (arg1[0]), x1);
  x4 = (arg2[1]);
  fiat_subborrowx_u64(&x5, &x6, x3, (arg1[1]), x4);
  x7 = (arg2[2]);
  fiat_subborrowx_u64(&x8, &x9, x6, (arg1[2]), x7);
  x10 = (arg2[3]);
  fiat_subborrowx_u64(&x11, &x12, x9, (arg1[3]), x10);
  fiat_cmovznz_u64(&x13, x12, 0x0, UINT8_C(0x26)); // NOTE: clang 14 for Zen 2 uses sbb, and
  fiat_subborrowx_u64(&x14, &x15, 0x0, x2, x13);
  fiat_subborrowx_u64(&x16, &x17, x15, x5, 0x0);
  fiat_subborrowx_u64(&x18, &x19, x17, x8, 0x0);
  fiat_subborrowx_u64(&x20, &x21, x19, x11, 0x0);
  fiat_cmovznz_u64(&x22, x21, 0x0, UINT8_C(0x26)); // NOTE: clang 14 for Zen 2 uses sbb, and
  fiat_subborrowx_u64(&x23, &x24, 0x0, x14, x22);
  out1[0] = x23;
  out1[1] = x16;
  out1[2] = x18;
  out1[3] = x20;
}

/*
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg2: [0x0 ~> 0x3ffffffffffffff] // NOTE: this is not any uint64!
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
static void fe4_scmul(uint64_t out1[4], const uint64_t arg1[4], uint64_t arg2) {
  uint64_t x1;
  uint64_t x2;
  uint64_t x3;
  uint64_t x4;
  uint64_t x5;
  fiat_uint1 x6;
  uint64_t x7;
  uint64_t x8;
  uint64_t x9;
  fiat_uint1 x10;
  uint64_t x11;
  uint64_t x12;
  uint64_t x13;
  fiat_uint1 x14;
  uint64_t x15;
  uint64_t x16;
  uint64_t x17;
  fiat_uint1 x18;
  uint64_t x19;
  fiat_uint1 x20;
  uint64_t x21;
  fiat_uint1 x22;
  uint64_t x23;
  fiat_uint1 x24;
  uint64_t x25;
  uint64_t x26;
  fiat_uint1 x27;
  fiat_mulx_u64(&x1, &x2, (arg1[0]), arg2);
  fiat_mulx_u64(&x3, &x4, (arg1[1]), arg2);
  fiat_addcarryx_u64(&x5, &x6, 0x0, x2, x3);
  fiat_mulx_u64(&x7, &x8, (arg1[2]), arg2);
  fiat_addcarryx_u64(&x9, &x10, x6, x4, x7);
  fiat_mulx_u64(&x11, &x12, (arg1[3]), arg2);
  fiat_addcarryx_u64(&x13, &x14, x10, x8, x11);
  fiat_mulx_u64(&x15, &x16, (x12 + (uint64_t)x14), UINT8_C(0x26));
  fiat_addcarryx_u64(&x17, &x18, 0x0, x1, x15);
  fiat_addcarryx_u64(&x19, &x20, x18, x5, 0x0);
  fiat_addcarryx_u64(&x21, &x22, x20, x9, 0x0);
  fiat_addcarryx_u64(&x23, &x24, x22, x13, 0x0);
  fiat_cmovznz_u64(&x25, x24, 0x0, UINT8_C(0x26)); // NOTE: clang 14 for Zen 2 uses sbb, and
  fiat_addcarryx_u64(&x26, &x27, 0x0, x17, x25);
  out1[0] = x26;
  out1[1] = x19;
  out1[2] = x21;
  out1[3] = x23;
}

/*
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
static void fe4_canon(uint64_t out1[4], const uint64_t arg1[4]) {
  uint64_t x1;
  fiat_uint1 x2;
  uint64_t x3;
  fiat_uint1 x4;
  uint64_t x5;
  fiat_uint1 x6;
  uint64_t x7;
  fiat_uint1 x8;
  uint64_t x9;
  uint64_t x10;
  uint64_t x11;
  uint64_t x12;
  uint64_t x13;
  fiat_uint1 x14;
  uint64_t x15;
  fiat_uint1 x16;
  uint64_t x17;
  fiat_uint1 x18;
  uint64_t x19;
  fiat_uint1 x20;
  uint64_t x21;
  uint64_t x22;
  uint64_t x23;
  uint64_t x24;
  fiat_subborrowx_u64(&x1, &x2, 0x0, (arg1[0]), UINT64_C(0xffffffffffffffed));
  fiat_subborrowx_u64(&x3, &x4, x2, (arg1[1]), UINT64_C(0xffffffffffffffff));
  fiat_subborrowx_u64(&x5, &x6, x4, (arg1[2]), UINT64_C(0xffffffffffffffff));
  fiat_subborrowx_u64(&x7, &x8, x6, (arg1[3]), UINT64_C(0x7fffffffffffffff));
  fiat_cmovznz_u64(&x9, x8, x1, (arg1[0]));
  fiat_cmovznz_u64(&x10, x8, x3, (arg1[1]));
  fiat_cmovznz_u64(&x11, x8, x5, (arg1[2]));
  fiat_cmovznz_u64(&x12, x8, x7, (arg1[3]));
  fiat_subborrowx_u64(&x13, &x14, 0x0, x9, UINT64_C(0xffffffffffffffed));
  fiat_subborrowx_u64(&x15, &x16, x14, x10, UINT64_C(0xffffffffffffffff));
  fiat_subborrowx_u64(&x17, &x18, x16, x11, UINT64_C(0xffffffffffffffff));
  fiat_subborrowx_u64(&x19, &x20, x18, x12, UINT64_C(0x7fffffffffffffff));
  fiat_cmovznz_u64(&x21, x20, x13, x9);
  fiat_cmovznz_u64(&x22, x20, x15, x10);
  fiat_cmovznz_u64(&x23, x20, x17, x11);
  fiat_cmovznz_u64(&x24, x20, x19, x12);
  out1[0] = x21;
  out1[1] = x22;
  out1[2] = x23;
  out1[3] = x24;
}

/*
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   out2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
static void fe4_cswap(uint64_t out1[4], uint64_t out2[4], fiat_uint1 arg1, const uint64_t arg2[4], const uint64_t arg3[4]) {
  uint64_t x1;
  uint64_t x2;
  uint64_t x3;
  uint64_t x4;
  uint64_t x5;
  uint64_t x6;
  uint64_t x7;
  uint64_t x8;
  // NOTE: clang 14 for Zen 2 uses YMM registers
  fiat_cmovznz_u64(&x1, arg1, (arg2[0]), (arg3[0]));
  fiat_cmovznz_u64(&x2, arg1, (arg2[1]), (arg3[1]));
  fiat_cmovznz_u64(&x3, arg1, (arg2[2]), (arg3[2]));
  fiat_cmovznz_u64(&x4, arg1, (arg2[3]), (arg3[3]));
  fiat_cmovznz_u64(&x5, arg1, (arg3[0]), (arg2[0]));
  fiat_cmovznz_u64(&x6, arg1, (arg3[1]), (arg2[1]));
  fiat_cmovznz_u64(&x7, arg1, (arg3[2]), (arg2[2]));
  fiat_cmovznz_u64(&x8, arg1, (arg3[3]), (arg2[3]));
  out1[0] = x1;
  out1[1] = x2;
  out1[2] = x3;
  out1[3] = x4;
  out2[0] = x5;
  out2[1] = x6;
  out2[2] = x7;
  out2[3] = x8;
}

// The following functions are adaped from crypto/curve25519/curve25519.c
// It would be desirable to share the code, but with the current field
// implementations both 4-limb and 5-limb versions of the curve-level code need
// to be included in builds targetting an unknown variant of x86_64.

static void fe4_invert(fe4 out, const fe4 z) {
  fe4 t0;
  fe4 t1;
  fe4 t2;
  fe4 t3;
  int i;

  fe4_sq(t0, z);
  fe4_sq(t1, t0);
  for (i = 1; i < 2; ++i) {
    fe4_sq(t1, t1);
  }
  fe4_mul(t1, z, t1);
  fe4_mul(t0, t0, t1);
  fe4_sq(t2, t0);
  fe4_mul(t1, t1, t2);
  fe4_sq(t2, t1);
  for (i = 1; i < 5; ++i) {
    fe4_sq(t2, t2);
  }
  fe4_mul(t1, t2, t1);
  fe4_sq(t2, t1);
  for (i = 1; i < 10; ++i) {
    fe4_sq(t2, t2);
  }
  fe4_mul(t2, t2, t1);
  fe4_sq(t3, t2);
  for (i = 1; i < 20; ++i) {
    fe4_sq(t3, t3);
  }
  fe4_mul(t2, t3, t2);
  fe4_sq(t2, t2);
  for (i = 1; i < 10; ++i) {
    fe4_sq(t2, t2);
  }
  fe4_mul(t1, t2, t1);
  fe4_sq(t2, t1);
  for (i = 1; i < 50; ++i) {
    fe4_sq(t2, t2);
  }
  fe4_mul(t2, t2, t1);
  fe4_sq(t3, t2);
  for (i = 1; i < 100; ++i) {
    fe4_sq(t3, t3);
  }
  fe4_mul(t2, t3, t2);
  fe4_sq(t2, t2);
  for (i = 1; i < 50; ++i) {
    fe4_sq(t2, t2);
  }
  fe4_mul(t1, t2, t1);
  fe4_sq(t1, t1);
  for (i = 1; i < 5; ++i) {
    fe4_sq(t1, t1);
  }
  fe4_mul(out, t1, t0);
}

void x25519_scalar_mult_adx(uint8_t out[32], const uint8_t scalar[32],
                            const uint8_t point[32]) {
  uint8_t e[32];
  memcpy(e, scalar, 32);
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;

  // The following implementation was transcribed to Coq and proven to
  // correspond to unary scalar multiplication in affine coordinates given that
  // x1 != 0 is the x coordinate of some point on the curve. It was also checked
  // in Coq that doing a ladderstep with x1 = x3 = 0 gives z2' = z3' = 0, and z2
  // = z3 = 0 gives z2' = z3' = 0. The statement was quantified over the
  // underlying field, so it applies to Curve25519 itself and the quadratic
  // twist of Curve25519. It was not proven in Coq that prime-field arithmetic
  // correctly simulates extension-field arithmetic on prime-field values.
  // The decoding of the byte array representation of e was not considered.
  // Specification of Montgomery curves in affine coordinates:
  // <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Spec/MontgomeryCurve.v#L27>
  // Proof that these form a group that is isomorphic to a Weierstrass curve:
  // <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/AffineProofs.v#L35>
  // Coq transcription and correctness proof of the loop (where scalarbits=255):
  // <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZ.v#L118>
  // <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L278>
  // preconditions: 0 <= e < 2^255 (not necessarily e < order), fe_invert(0) = 0
  fe4 x1, x2 = {1}, z2 = {0}, x3, z3 = {1}, tmp0, tmp1;
  OPENSSL_memcpy(x1, point, sizeof(fe4));
  x1[3] &= (uint64_t)(-1)>>1;
  OPENSSL_memcpy(x3, x1, sizeof(fe4));

  unsigned swap = 0;
  int pos;
  for (pos = 254; pos >= 0; --pos) {
    // loop invariant as of right before the test, for the case where x1 != 0:
    //   pos >= -1; if z2 = 0 then x2 is nonzero; if z3 = 0 then x3 is nonzero
    //   let r := e >> (pos+1) in the following equalities of projective points:
    //   to_xz (r*P)     === if swap then (x3, z3) else (x2, z2)
    //   to_xz ((r+1)*P) === if swap then (x2, z2) else (x3, z3)
    //   x1 is the nonzero x coordinate of the nonzero point (r*P-(r+1)*P)
    unsigned b = 1 & (e[pos / 8] >> (pos & 7));
    swap ^= b;
    fe4_cswap(x2, x3, swap, x2, x3);
    fe4_cswap(z2, z3, swap, z2, z3);
    swap = b;
    // Coq transcription of ladderstep formula (called from transcribed loop):
    // <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZ.v#L89>
    // <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L131>
    // x1 != 0 <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L217>
    // x1  = 0 <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L147>
    fe4_sub(tmp0, x3, z3);
    fe4_sub(tmp1, x2, z2);
    fe4_add(x2, x2, z2);
    fe4_add(z2, x3, z3);
    fe4_mul(z3, tmp0, x2);
    fe4_mul(z2, z2, tmp1);
    fe4_sq(tmp0, tmp1);
    fe4_sq(tmp1, x2);
    fe4_add(x3, z3, z2);
    fe4_sub(z2, z3, z2);
    fe4_mul(x2, tmp1, tmp0);
    fe4_sub(tmp1, tmp1, tmp0);
    fe4_sq(z2, z2);
    fe4_scmul(z3, tmp1, 121666);
    fe4_sq(x3, x3);
    fe4_add(tmp0, tmp0, z3);
    fe4_mul(z3, x1, z2);
    fe4_mul(z2, tmp1, tmp0);
  }
  // here pos=-1, so r=e, so to_xz (e*P) === if swap then (x3, z3) else (x2, z2)
  fe4_cswap(x2, x3, swap, x2, x3);
  fe4_cswap(z2, z3, swap, z2, z3);

  fe4_invert(z2, z2);
  fe4_mul(x2, x2, z2);
  fe4_canon(x2, x2);
  OPENSSL_memcpy(out, x2, sizeof(fe4));
}
