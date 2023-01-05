package ecies

import (
	"bytes"
	"crypto/elliptic"
	"io"
)

var curve = elliptic.P521()

// EncryptSimple encrypts a byte slice for a given public key.
func EncryptSimple(pubKey *PublicKey, data []byte) ([]byte, error) {
	var out bytes.Buffer
	in := bytes.NewBuffer(data)
	err := Encrypt(pubKey, in, &out)
	return out.Bytes(), err
}

// DecryptSimple decrypts a byte slice with a given private key.
func DecryptSimple(privKey *PrivateKey, data []byte) ([]byte, error) {
	var out bytes.Buffer
	in := bytes.NewBuffer(data)
	err := Decrypt(privKey, in, &out)
	return out.Bytes(), err
}

// Encrypt encrypts an input stream for a given public key.
func Encrypt(pubKey *PublicKey, in io.Reader, out io.Writer) error {
	// Generate ephemeral key for acquiring AES/HMAC key from KDF.
	privKey, err := GenerateKey()
	if err != nil {
		return err
	}

	// Get the AES and HMAC keys from the KDF.
	_, err = out.Write(privKey.PublicKey.Bytes(true))
	if err != nil {
		return err
	}

	// Derive the shared secret from the two keys.
	// Since we're using our own KDF, it's not
	// necessary to use PublicKey#DeriveKey
	// which uses its own KDF function, ECDH_KDF.
	sharedKey := privKey.ECDH(pubKey)

	// Perform stream encryption.
	return EncryptStreamSimple(in, out, sharedKey)
}

// Decrypt decrypts an input stream with a given private key.
func Decrypt(privKey *PrivateKey, in io.Reader, out io.Writer) error {
	// Read the public key from the stream.
	buf := make([]byte, PublicKeyLengthCompressed)
	_, err := in.Read(buf)
	if err != nil {
		return err
	}

	// Parse the public key from the read data.
	pubKey, err := ParsePublicKey(buf)
	if err != nil {
		return err
	}

	// Derive the shared secret from the two keys.
	// Since we're using our own KDF, it's not
	// necessary to use PublicKey#DeriveKey
	// which uses its own KDF function, ECDH_KDF.
	sharedKey := pubKey.ECDH(privKey)

	// Perform stream decryption.
	return DecryptStreamSimple(in, out, sharedKey)
}
