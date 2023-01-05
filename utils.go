package ecies

import (
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/hkdf"
)

// SingleKDF is used to generate a single key that is safe to use as an
// encryption key from an otherwise unsafe key, such as an ECDH shared key.
func SingleKDF(secret []byte) ([]byte, error) {
	kdf := hkdf.New(sha512.New, secret, nil, nil)

	key := make([]byte, 32)
	_, err := kdf.Read(key)
	if err != nil {
		return nil, fmt.Errorf("cannot read secret from HKDF: %w", err)
	}

	return key, nil
}

// CryptoKDF is used to generate AES and HMAC keys from a secret.
//
// this function is used within the library since two keys are required for
// stream encryption, but only one secret (the shared ECDH key) exists.
func CryptoKDF(secret []byte) ([]byte, []byte, error) {
	kdf := hkdf.New(sha512.New, secret, nil, nil)

	key1 := make([]byte, 32)
	_, err := kdf.Read(key1)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read secret from HKDF: %w", err)
	}

	key2 := make([]byte, 32)
	_, err = kdf.Read(key2)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read secret from HKDF: %w", err)
	}

	return key1, key2, nil
}
