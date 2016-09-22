package itsdangerous

import (
	"crypto/hmac"
	"crypto/subtle"
	"hash"
)

// SigningAlgorithm provides interfaces to generate and verify signature
type SigningAlgorithm interface {
	GetSignature([]byte, []byte) []byte
	VerifySignature(key, value, sig []byte) bool
}

// HMACAlgorithm provides signature generation using HMACs.
type HMACAlgorithm struct {
	DigestMethod hash.Hash
}

// GetSignature returns the signature for the given key and value.
func (a *HMACAlgorithm) GetSignature(key, value []byte) []byte {
	a.DigestMethod.Reset()
	h := hmac.New(func() hash.Hash { return a.DigestMethod }, key)
	h.Write(value)
	return h.Sum(nil)
}

// VerifySignature verifies the given signature matches the expected signature.
func (a *HMACAlgorithm) VerifySignature(key, value, sig []byte) bool {
	eq := subtle.ConstantTimeCompare(sig, a.GetSignature(key, value))
	return eq == 1
}
