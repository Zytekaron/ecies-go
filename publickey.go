package ecies

import (
	"crypto/elliptic"
	"crypto/subtle"
	"errors"
	"math/big"
)

const (
	// PublicKeyLengthCompressed is the length of the compressed public key when marshalled.
	// See elliptic.MarshalCompressed.
	PublicKeyLengthCompressed = 67

	// PublicKeyLengthUncompressed is the length of the uncompressed public key when marshalled.
	// See elliptic.Marshal.
	PublicKeyLengthUncompressed = 133
)

var ErrInvalidPublicKey = errors.New("invalid public key")

// PublicKey is a P-521 elliptic curve public key implementation.
type PublicKey struct {
	X, Y *big.Int
}

// ParsePublicKey parses a public key from a byte slice.
//
// Both compressed and uncompressed keys are supported.
//
// See elliptic.Marshal and elliptic.MarshalCompressed.
func ParsePublicKey(data []byte) (*PublicKey, error) {
	var x, y *big.Int
	if len(data) == PublicKeyLengthCompressed {
		x, y = elliptic.UnmarshalCompressed(curve, data)
	} else {
		x, y = elliptic.Unmarshal(curve, data)
	}

	if x == nil || y == nil {
		return nil, ErrInvalidPublicKey
	}

	return &PublicKey{
		X: x,
		Y: y,
	}, nil
}

// Bytes marshals this key and returns the associated bytes.
//
// The length of the returned slice will be
// PublicKeyLengthCompressed if true is passed, or
// PublicKeyLengthUncompressed if false is passed.
//
// See elliptic.Marshal and elliptic.MarshalCompressed.
func (pk *PublicKey) Bytes(compressed bool) []byte {
	if compressed {
		return elliptic.MarshalCompressed(curve, pk.X, pk.Y)
	}
	return elliptic.Marshal(curve, pk.X, pk.Y)
}

// ECDH calculates the shared key for this key and the provided private key.
//
// Use DeriveKey if this shared secret will be used as an encryption key.
func (pk *PublicKey) ECDH(sk *PrivateKey) []byte {
	if pk == nil {
		panic("nil key passed")
	}

	x, _ := curve.ScalarMult(pk.X, pk.Y, sk.D.Bytes())
	return x.Bytes()
}

// DeriveKey passes the result of ECDH through a KDF.
//
// The returned key can be safely used as an encryption key.
func (pk *PublicKey) DeriveKey(sk *PrivateKey) ([]byte, error) {
	return SingleKDF(sk.ECDH(pk))
}

// Equals returns whether the two public keys are identical.
func (pk *PublicKey) Equals(pubKey *PublicKey) bool {
	eqX := subtle.ConstantTimeCompare(pk.X.Bytes(), pubKey.X.Bytes()) == 1
	eqY := subtle.ConstantTimeCompare(pk.Y.Bytes(), pubKey.Y.Bytes()) == 1
	return eqX && eqY
}
