package ecies

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"math/big"
)

// PrivateKey is a P-521 elliptic curve private
// key implementation with a nested PublicKey.
type PrivateKey struct {
	*PublicKey
	D *big.Int
}

// GenerateKey generates a P-521 key pair.
func GenerateKey() (*PrivateKey, error) {
	data, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		PublicKey: &PublicKey{
			X: x,
			Y: y,
		},
		D: new(big.Int).SetBytes(data),
	}, nil
}

// ParsePrivateKey parses a P-521 private key from a byte slice.
func ParsePrivateKey(data []byte) *PrivateKey {
	x, y := curve.ScalarBaseMult(data)

	return &PrivateKey{
		PublicKey: &PublicKey{
			X: x,
			Y: y,
		},
		D: new(big.Int).SetBytes(data),
	}
}

// Bytes returns the bytes for the D value of this key.
//
// The length of the returned slice will be PrivateKeyLength.
func (sk *PrivateKey) Bytes() []byte {
	return sk.D.Bytes()
}

// ECDH calculates the shared key for this key and the provided public key.
//
// Use DeriveKey if this shared secret will be used as an encryption key.
func (sk *PrivateKey) ECDH(pk *PublicKey) []byte {
	if pk == nil {
		panic("nil key passed")
	}

	x, _ := curve.ScalarMult(pk.X, pk.Y, sk.D.Bytes())
	return x.Bytes()
}

// DeriveKey passes the result of ECDH through a KDF.
//
// The returned key can be safely used as an encryption key.
func (sk *PrivateKey) DeriveKey(pk *PublicKey) ([]byte, error) {
	return SingleKDF(sk.ECDH(pk))
}

// Equals returns whether the two private keys are identical.
func (sk *PrivateKey) Equals(privKey *PrivateKey) bool {
	return subtle.ConstantTimeCompare(sk.D.Bytes(), privKey.D.Bytes()) == 1
}
