package itsdangerous

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// Signature can sign bytes and unsign it and validate the signature
// provided.
//
// Salt can be used to namespace the hash, so that a signed string is only
// valid for a given namespace.  Leaving this at the default value or re-using
// a salt value across different parts of your application where the same
// signed value in one part can mean something different in another part
// is a security risk.
type Signature struct {
	SecretKey     []byte
	Sep           []byte
	Salt          []byte
	KeyDerivation string
	DigestMethod  hash.Hash
	Algorithm     SigningAlgorithm
}

// DeriveKey generates a key derivation. Keep in mind that the key derivation in itsdangerous
// is not intended to be used as a security method to make a complex key out of a short password.
// Instead you should use large random secret keys.
func (s *Signature) DeriveKey() ([]byte, error) {
	var key []byte
	var err error

	s.DigestMethod.Reset()

	switch s.KeyDerivation {
	case "concat":
		h := s.DigestMethod
		h.Write(s.Salt)
		h.Write(s.SecretKey)
		key = h.Sum(nil)
	case "django-concat":
		h := s.DigestMethod
		h.Write(s.Salt)
		h.Write([]byte("signer"))
		h.Write(s.SecretKey)
		key = h.Sum(nil)
	case "hmac":
		h := hmac.New(func() hash.Hash { return s.DigestMethod }, s.SecretKey)
		h.Write(s.Salt)
		key = h.Sum(nil)
	case "none":
		key = s.SecretKey
	default:
		key, err = nil, errors.New("unknown key derivation method")
	}
	return key, err
}

// Get returns the signature for the given value.
func (s *Signature) Get(value []byte) ([]byte, error) {
	key, err := s.DeriveKey()
	if err != nil {
		return nil, err
	}

	sig := s.Algorithm.GetSignature(key, value)
	return base64Encode(sig), err
}

// Verify verifies the signature for the given value.
func (s *Signature) Verify(value, sig []byte) (bool, error) {
	key, err := s.DeriveKey()
	if err != nil {
		return false, err
	}

	signed, err := base64Decode(sig)
	if err != nil {
		return false, err
	}
	return s.Algorithm.VerifySignature(key, value, signed), nil
}

// Sign the given string.
func (s *Signature) Sign(value []byte) ([]byte, error) {
	sig, err := s.Get(value)
	if err != nil {
		return nil, err
	}
	return sepJoin(value, s.Sep, sig), nil
}

// Unsign the given string.
func (s *Signature) Unsign(signed []byte) ([]byte, error) {
	if !bytes.Contains(signed, s.Sep) {
		return nil, fmt.Errorf("no %s found in value", s.Sep)
	}

	li := bytes.LastIndex(signed, s.Sep)
	value, sig := signed[:li], signed[li+len(s.Sep):]

	if ok, _ := s.Verify(value, sig); ok == true {
		return value, nil
	}
	return nil, fmt.Errorf("signature %s does not match", sig)
}

// SignB64 first Base64 encodes the (optionally compressed) value before signing.
// This is compatable with itsdangerous URLSafeSerializer
func (s *Signature) SignB64(value []byte) ([]byte, error) {
	return s.Sign(ZBase64Encode(value))
}

// UnsignB64 Base64 decodes the (optionally compressed) value after unsigning
// This is compatable with itsdangerous URLSafeSerializer
func (s *Signature) UnsignB64(signed []byte) ([]byte, error) {
	b, err := s.Unsign(signed)
	if err != nil {
		return nil, err
	}
	return base64Decode(b)
}

// NewSignature creates a new Signature
func NewSignature(secret, salt, sep, derivation string, digest hash.Hash, algo SigningAlgorithm) *Signature {
	if salt == "" {
		salt = "itsdangerous.Signer"
	}
	if sep == "" {
		sep = "."
	}
	if derivation == "" {
		derivation = "django-concat"
	}
	if digest == nil {
		digest = sha1.New()
	}
	if algo == nil {
		algo = &HMACAlgorithm{DigestMethod: digest}
	}
	return &Signature{
		SecretKey:     []byte(secret),
		Salt:          []byte(salt),
		Sep:           []byte(sep),
		KeyDerivation: derivation,
		DigestMethod:  digest,
		Algorithm:     algo,
	}
}

// TimestampSignature works like the regular Signature but also records the time
// of the signing and can be used to expire signatures.
type TimestampSignature struct {
	Signature
}

// Sign the given string.
func (s *TimestampSignature) Sign(value []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, getTimestamp()); err != nil {
		return nil, err
	}

	ts := base64Encode(buf.Bytes())

	val := sepJoin(value, s.Sep, ts)

	sig, err := s.Get(val)
	if err != nil {
		return nil, err
	}
	return sepJoin(val, s.Sep, sig), nil
}

// SignB64 first Base64 encodes the (optionally compressed) value before signing.
// This is compatable with itsdangerous URLSafeTimedSerializer
func (s *TimestampSignature) SignB64(value []byte) ([]byte, error) {
	return s.Sign(ZBase64Encode(value))
}

// UnsignB64 Base64 decodes the (optionally compressed) value after unsigning
// This is compatable with itsdangerous URLSafeTimedSerializer
func (s *TimestampSignature) UnsignB64(signed []byte, maxAge uint32) ([]byte, error) {
	b, err := s.Unsign(signed, maxAge)
	if err != nil {
		return nil, err
	}
	return base64Decode(b)
}

// Unsign the given string.
func (s *TimestampSignature) Unsign(value []byte, maxAge uint32) ([]byte, error) {
	var timestamp uint32

	result, err := s.Signature.Unsign(value)
	if err != nil {
		return nil, err
	}

	// If there is no timestamp in the result there is something seriously wrong.
	if !bytes.Contains(result, s.Sep) {
		return nil, errors.New("timestamp missing")
	}

	li := bytes.LastIndex(result, s.Sep)
	val, ts := result[:li], result[li+len(s.Sep):]

	sig, err := base64Decode(ts)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewReader(sig)
	if err = binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return nil, err
	}

	if maxAge > 0 {
		if age := getTimestamp() - timestamp; age > maxAge {
			return nil, fmt.Errorf("signature age %d > %d seconds", age, maxAge)
		}
	}

	return val, nil
}

// NewTimestampSignature creates a new TimestampSignature
func NewTimestampSignature(secret, salt, sep, derivation string, digest hash.Hash, algo SigningAlgorithm) *TimestampSignature {
	s := NewSignature(secret, salt, sep, derivation, digest, algo)
	return &TimestampSignature{Signature: *s}
}

func sepJoin(value, sep, sig []byte) []byte {
	buf := bytes.Buffer{}
	buf.Write(value)
	buf.Write(sep)
	buf.Write(sig)
	return buf.Bytes()
}
