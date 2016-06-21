// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

type signer interface {
	supportsKey(key crypto.PrivateKey) bool
	signMessage(key crypto.PrivateKey, config *Config, msg []byte) ([]byte, error)
	verifyMessage(key crypto.PublicKey, msg, sig []byte) error
}

func selectSignatureAlgorithm(version uint16, key crypto.PrivateKey, peerSigAlgs, ourSigAlgs []signatureAlgorithm) (signatureAlgorithm, error) {
	// If the client didn't specify any signature_algorithms extension then
	// we can assume that it supports SHA1. See
	// http://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
	if len(peerSigAlgs) == 0 {
		peerSigAlgs = []signatureAlgorithm{signatureRSAPKCS1WithSHA1, signatureECDSAWithSHA1}
	}

	for _, sigAlg := range ourSigAlgs {
		if !isSupportedSignatureAlgorithm(sigAlg, peerSigAlgs) {
			continue
		}

		signer, err := getSigner(version, key, sigAlg)
		if err != nil {
			continue
		}

		if signer.supportsKey(key) {
			return sigAlg, nil
		}
	}
	return 0, errors.New("tls: no common signature algorithms")
}

func signMessage(version uint16, key crypto.PrivateKey, config *Config, sigAlg signatureAlgorithm, msg []byte) ([]byte, error) {
	signer, err := getSigner(version, key, sigAlg)
	if err != nil {
		return nil, err
	}

	return signer.signMessage(key, config, msg)
}

func verifyMessage(version uint16, key crypto.PublicKey, sigAlg signatureAlgorithm, msg, sig []byte) error {
	signer, err := getSigner(version, key, sigAlg)
	if err != nil {
		return err
	}

	return signer.verifyMessage(key, msg, sig)
}

type rsaPKCS1Signer struct {
	hash crypto.Hash
}

func (r *rsaPKCS1Signer) computeHash(msg []byte) []byte {
	if r.hash == crypto.MD5SHA1 {
		// crypto.MD5SHA1 is not a real hash function.
		hashMD5 := md5.New()
		hashMD5.Write(msg)
		hashSHA1 := sha1.New()
		hashSHA1.Write(msg)
		return hashSHA1.Sum(hashMD5.Sum(nil))
	}

	h := r.hash.New()
	h.Write(msg)
	return h.Sum(nil)
}

func (r *rsaPKCS1Signer) supportsKey(key crypto.PrivateKey) bool {
	_, ok := key.(*rsa.PrivateKey)
	return ok
}

func (r *rsaPKCS1Signer) signMessage(key crypto.PrivateKey, config *Config, msg []byte) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid key type for RSA-PKCS1")
	}

	return rsa.SignPKCS1v15(config.rand(), rsaKey, r.hash, r.computeHash(msg))
}

func (r *rsaPKCS1Signer) verifyMessage(key crypto.PublicKey, msg, sig []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid key type for RSA-PKCS1")
	}

	return rsa.VerifyPKCS1v15(rsaKey, r.hash, r.computeHash(msg), sig)
}

type ecdsaSigner struct {
	// TODO(davidben): In TLS 1.3, ECDSA signatures must match curves as
	// well. Pass in a curve to enforce in 1.3 alone.
	hash crypto.Hash
}

func (e *ecdsaSigner) supportsKey(key crypto.PrivateKey) bool {
	_, ok := key.(*ecdsa.PrivateKey)
	return ok
}

func maybeCorruptECDSAValue(n *big.Int, typeOfCorruption BadValue, limit *big.Int) *big.Int {
	switch typeOfCorruption {
	case BadValueNone:
		return n
	case BadValueNegative:
		return new(big.Int).Neg(n)
	case BadValueZero:
		return big.NewInt(0)
	case BadValueLimit:
		return limit
	case BadValueLarge:
		bad := new(big.Int).Set(limit)
		return bad.Lsh(bad, 20)
	default:
		panic("unknown BadValue type")
	}
}

func (e *ecdsaSigner) signMessage(key crypto.PrivateKey, config *Config, msg []byte) ([]byte, error) {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid key type for ECDSA")
	}

	h := e.hash.New()
	h.Write(msg)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(config.rand(), ecdsaKey, digest)
	if err != nil {
		return nil, errors.New("failed to sign ECDHE parameters: " + err.Error())
	}
	order := ecdsaKey.Curve.Params().N
	r = maybeCorruptECDSAValue(r, config.Bugs.BadECDSAR, order)
	s = maybeCorruptECDSAValue(s, config.Bugs.BadECDSAS, order)
	return asn1.Marshal(ecdsaSignature{r, s})
}

func (e *ecdsaSigner) verifyMessage(key crypto.PublicKey, msg, sig []byte) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid key type for ECDSA")
	}

	ecdsaSig := new(ecdsaSignature)
	if _, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
		return err
	}
	if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
		return errors.New("ECDSA signature contained zero or negative values")
	}

	h := e.hash.New()
	h.Write(msg)
	if !ecdsa.Verify(ecdsaKey, h.Sum(nil), ecdsaSig.R, ecdsaSig.S) {
		return errors.New("ECDSA verification failure")
	}
	return nil
}

func getSigner(version uint16, key interface{}, sigAlg signatureAlgorithm) (signer, error) {
	// TLS 1.1 and below use legacy signature algorithms.
	if version < VersionTLS12 {
		switch key.(type) {
		case *rsa.PrivateKey, *rsa.PublicKey:
			return &rsaPKCS1Signer{crypto.MD5SHA1}, nil
		case *ecdsa.PrivateKey, *ecdsa.PublicKey:
			return &ecdsaSigner{crypto.SHA1}, nil
		default:
			return nil, errors.New("unknown key type")
		}
	}

	// TODO(davidben): Implement RSA-PSS for TLS 1.3.
	switch sigAlg {
	case signatureRSAPKCS1WithMD5:
		return &rsaPKCS1Signer{crypto.MD5}, nil
	case signatureRSAPKCS1WithSHA1:
		return &rsaPKCS1Signer{crypto.SHA1}, nil
	case signatureRSAPKCS1WithSHA256:
		return &rsaPKCS1Signer{crypto.SHA256}, nil
	case signatureRSAPKCS1WithSHA384:
		return &rsaPKCS1Signer{crypto.SHA384}, nil
	case signatureRSAPKCS1WithSHA512:
		return &rsaPKCS1Signer{crypto.SHA512}, nil
	case signatureECDSAWithSHA1:
		return &ecdsaSigner{crypto.SHA1}, nil
	case signatureECDSAWithP256AndSHA256:
		return &ecdsaSigner{crypto.SHA256}, nil
	case signatureECDSAWithP384AndSHA384:
		return &ecdsaSigner{crypto.SHA384}, nil
	case signatureECDSAWithP521AndSHA512:
		return &ecdsaSigner{crypto.SHA512}, nil
	default:
		return nil, fmt.Errorf("unsupported signature algorithm %04x", sigAlg)
	}
}
