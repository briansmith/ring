/* ====================================================================
 * Copyright (c) 1999-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

#ifndef OPENSSL_HEADER_MD32_COMMON_H
#define OPENSSL_HEADER_MD32_COMMON_H

#include <openssl/base.h>


#if defined(__cplusplus)
extern "C" {
#endif

#define asm __asm__

/* This is a generic 32-bit "collector" for message digest algorithms. It
 * collects input character stream into chunks of 32-bit values and invokes the
 * block function that performs the actual hash calculations. To make use of
 * this mechanism, the following macros must be defined before including
 * md32_common.h.
 *
 * One of |DATA_ORDER_IS_BIG_ENDIAN| or |DATA_ORDER_IS_LITTLE_ENDIAN| must be
 * defined to specify the byte order of the input stream.
 *
 * |HASH_CBLOCK| must be defined as the integer block size, in bytes.
 *
 * |HASH_CTX| must be defined as the name of the context structure, which must
 * have at least the following members:
 *
 *     typedef struct <name>_state_st {
 *       uint32_t h[<chaining length> / sizeof(uint32_t)];
 *       uint32_t Nl,Nh;
 *       uint32_t data[HASH_CBLOCK / sizeof(uint32_t)];
 *       unsigned int num
 *       ...
 *     } <NAME>_CTX;
 *
 * <chaining length> is the output length of the hash in bytes, before
 * any truncation (e.g. 64 for SHA-224 and SHA-256, 128 for SHA-384 and SHA-512).
 *
 * |HASH_UPDATE| must be defined as the name of the "Update" function to
 * generate.
 *
 * |HASH_TRANSFORM| must be defined as the  the name of the "Transform"
 * function to generate.
 *
 * |HASH_FINAL| must be defined as the name of "Final" function to generate.
 *
 * |HASH_BLOCK_DATA_ORDER| must be defined as the name of the "Block" function.
 * That function must be implemented manually. It must be capable of operating
 * on *unaligned* input data in its original (data) byte order. It must have
 * this signature:
 *
 *     void HASH_BLOCK_DATA_ORDER(uint32_t *state, const uint8_t *data,
 *                                size_t num);
 *
 * It must update the hash state |state| with |num| blocks of data from |data|,
 * where each block is |HASH_CBLOCK| bytes; i.e. |data| points to a array of
 * |HASH_CBLOCK * num| bytes. |state| points to the |h| member of a |HASH_CTX|,
 * and so will have |<chaining length> / sizeof(uint32_t)| elements.
 *
 * |HASH_MAKE_STRING(c, s)| must be defined as a block statement that converts
 * the hash state |c->h| into the output byte order, storing the result in |s|.
 */

#if !defined(DATA_ORDER_IS_BIG_ENDIAN) && !defined(DATA_ORDER_IS_LITTLE_ENDIAN)
#error "DATA_ORDER must be defined!"
#endif

#ifndef HASH_CBLOCK
#error "HASH_CBLOCK must be defined!"
#endif
#ifndef HASH_CTX
#error "HASH_CTX must be defined!"
#endif

#ifndef HASH_UPDATE
#error "HASH_UPDATE must be defined!"
#endif
#ifndef HASH_TRANSFORM
#error "HASH_TRANSFORM must be defined!"
#endif
#ifndef HASH_FINAL
#error "HASH_FINAL must be defined!"
#endif

#ifndef HASH_BLOCK_DATA_ORDER
#error "HASH_BLOCK_DATA_ORDER must be defined!"
#endif

/*
 * Engage compiler specific rotate intrinsic function if available.
 */
#undef ROTATE
# if defined(_MSC_VER)
#  define ROTATE(a,n)	_lrotl(a,n)
# elif defined(__ICC)
#  define ROTATE(a,n)	_rotl(a,n)
# elif defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM)
  /*
   * Some GNU C inline assembler templates. Note that these are
   * rotates by *constant* number of bits! But that's exactly
   * what we need here...
   * 					<appro@fy.chalmers.se>
   */
#  if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
#   define ROTATE(a,n)	({ register uint32_t ret;	\
				asm (			\
				"roll %1,%0"		\
				: "=r"(ret)		\
				: "I"(n), "0"((uint32_t)(a))	\
				: "cc");		\
			   ret;				\
			})
#  endif /* OPENSSL_X86 || OPENSSL_X86_64 */
# endif /* COMPILER */

#ifndef ROTATE
#define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#endif

#if defined(DATA_ORDER_IS_BIG_ENDIAN)

#ifndef PEDANTIC
# if defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM)
# if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
    /*
     * This gives ~30-40% performance improvement in SHA-256 compiled
     * with gcc [on P4]. Well, first macro to be frank. We can pull
     * this trick on x86* platforms only, because these CPUs can fetch
     * unaligned data without raising an exception.
     */
#   define HOST_c2l(c,l)	({ uint32_t r=*((const uint32_t *)(c));	\
				   asm ("bswapl %0":"=r"(r):"0"(r));	\
				   (c)+=4; (l)=r;			})
#   define HOST_l2c(l,c)	({ uint32_t r=(l);			\
				   asm ("bswapl %0":"=r"(r):"0"(r));	\
				   *((uint32_t *)(c))=r; (c)+=4; r;	})
#  elif defined(__aarch64__)
#   if defined(__BYTE_ORDER__)
#    if defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__
#     define HOST_c2l(c,l)	({ uint32_t r;			\
				   asm ("rev	%w0,%w1"	\
					:"=r"(r)		\
					:"r"(*((const uint32_t *)(c))));\
				   (c)+=4; (l)=r;		})
#     define HOST_l2c(l,c)	({ uint32_t r;			\
				   asm ("rev	%w0,%w1"	\
					:"=r"(r)		\
					:"r"((uint32_t)(l)));	\
				   *((uint32_t *)(c))=r; (c)+=4; r;	})
#    elif defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__==__ORDER_BIG_ENDIAN__
#     define HOST_c2l(c,l)	(void)((l)=*((const uint32_t *)(c)), (c)+=4)
#     define HOST_l2c(l,c)	(*((uint32_t *)(c))=(l), (c)+=4, (l))
#    endif
#   endif
#  endif
# endif
#endif

#ifndef HOST_c2l
#define HOST_c2l(c,l)	(void)(l =(((uint32_t)(*((c)++)))<<24),	\
			 l|=(((uint32_t)(*((c)++)))<<16),	\
			 l|=(((uint32_t)(*((c)++)))<< 8),	\
			 l|=(((uint32_t)(*((c)++)))    ))
#endif
#ifndef HOST_l2c
#define HOST_l2c(l,c)	(*((c)++)=(uint8_t)(((l)>>24)&0xff),	\
			 *((c)++)=(uint8_t)(((l)>>16)&0xff),	\
			 *((c)++)=(uint8_t)(((l)>> 8)&0xff),	\
			 *((c)++)=(uint8_t)(((l)    )&0xff),	\
			 l)
#endif

#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
   /* See comment in DATA_ORDER_IS_BIG_ENDIAN section. */
#  define HOST_c2l(c,l)	(void)((l)=*((const uint32_t *)(c)), (c)+=4)
#  define HOST_l2c(l,c)	(*((uint32_t *)(c))=(l), (c)+=4, l)
#endif

#ifndef HOST_c2l
#define HOST_c2l(c,l)	(void)(l =(((uint32_t)(*((c)++)))    ),	\
			 l|=(((uint32_t)(*((c)++)))<< 8),	\
			 l|=(((uint32_t)(*((c)++)))<<16),	\
			 l|=(((uint32_t)(*((c)++)))<<24))
#endif
#ifndef HOST_l2c
#define HOST_l2c(l,c)	(*((c)++)=(uint8_t)(((l)    )&0xff),	\
			 *((c)++)=(uint8_t)(((l)>> 8)&0xff),	\
			 *((c)++)=(uint8_t)(((l)>>16)&0xff),	\
			 *((c)++)=(uint8_t)(((l)>>24)&0xff),	\
			 l)
#endif

#endif

int HASH_UPDATE (HASH_CTX *c, const void *data_, size_t len)
	{
	const uint8_t *data=data_;
	uint8_t *p;
	uint32_t l;
	size_t n;

	if (len==0) return 1;

	l=(c->Nl+(((uint32_t)len)<<3))&0xffffffffUL;
	/* 95-05-24 eay Fixed a bug with the overflow handling, thanks to
	 * Wei Dai <weidai@eskimo.com> for pointing it out. */
	if (l < c->Nl) /* overflow */
		c->Nh++;
	c->Nh+=(uint32_t)(len>>29);	/* might cause compiler warning on 16-bit */
	c->Nl=l;

	n = c->num;
	if (n != 0)
		{
		p=(uint8_t *)c->data;

		if (len >= HASH_CBLOCK || len+n >= HASH_CBLOCK)
			{
			memcpy (p+n,data,HASH_CBLOCK-n);
			HASH_BLOCK_DATA_ORDER (c->h,p,1);
			n      = HASH_CBLOCK-n;
			data  += n;
			len   -= n;
			c->num = 0;
			memset (p,0,HASH_CBLOCK);	/* keep it zeroed */
			}
		else
			{
			memcpy (p+n,data,len);
			c->num += (unsigned int)len;
			return 1;
			}
		}

	n = len/HASH_CBLOCK;
	if (n > 0)
		{
		HASH_BLOCK_DATA_ORDER (c->h,data,n);
		n    *= HASH_CBLOCK;
		data += n;
		len  -= n;
		}

	if (len != 0)
		{
		p = (uint8_t *)c->data;
		c->num = (unsigned int)len;
		memcpy (p,data,len);
		}
	return 1;
	}


void HASH_TRANSFORM (HASH_CTX *c, const uint8_t *data)
	{
	HASH_BLOCK_DATA_ORDER (c->h,data,1);
	}


int HASH_FINAL (uint8_t *md, HASH_CTX *c)
	{
	uint8_t *p = (uint8_t *)c->data;
	size_t n = c->num;

	p[n] = 0x80; /* there is always room for one */
	n++;

	if (n > (HASH_CBLOCK-8))
		{
		memset (p+n,0,HASH_CBLOCK-n);
		n=0;
		HASH_BLOCK_DATA_ORDER (c->h,p,1);
		}
	memset (p+n,0,HASH_CBLOCK-8-n);

	p += HASH_CBLOCK-8;
#if   defined(DATA_ORDER_IS_BIG_ENDIAN)
	(void)HOST_l2c(c->Nh,p);
	(void)HOST_l2c(c->Nl,p);
#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)
	(void)HOST_l2c(c->Nl,p);
	(void)HOST_l2c(c->Nh,p);
#endif
	p -= HASH_CBLOCK;
	HASH_BLOCK_DATA_ORDER (c->h,p,1);
	c->num=0;
	memset (p,0,HASH_CBLOCK);

#ifndef HASH_MAKE_STRING
#error "HASH_MAKE_STRING must be defined!"
#else
	HASH_MAKE_STRING(c,md);
#endif

	return 1;
	}


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_MD32_COMMON_H */
