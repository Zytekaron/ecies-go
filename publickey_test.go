package ecies

import (
	"bytes"
	"fmt"
	"log"
	"testing"
)

func ExampleParsePublicKey() {
	privateKey, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.PublicKey

	// see PublicKey.Bytes() for more information.
	bytes := publicKey.Bytes(true)

	publicKey, err = ParsePublicKey(bytes) // same key as before
	if err != nil {
		log.Fatal(err)
	}
}

func ExamplePublicKey_Bytes() {
	privateKey, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.PublicKey

	// pass true to compress the public key when marshalling.
	// see ecies.PublicKeyLengthCompressed
	// and ecies.PublicKeyLengthUncompressed
	bytes := publicKey.Bytes(true)

	saveFile("myKey.pub", bytes)
}

func ExamplePublicKey_ECDH() {
	// PublicKey.ECDH(*PrivateKey) is the same as PrivateKey.ECDH(*PublicKey)

	// this is your key.
	privateKey1, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	publicKey1 := privateKey1.PublicKey

	// this key belongs to someone else.
	privateKey2, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	publicKey2 := privateKey2.PublicKey

	// the other person will send you their public key, which
	// you can use to derive the shared secret using ECDH.
	sharedSecret1 := publicKey1.ECDH(privateKey2)

	// likewise, you will send your public key to the other
	// person, and they'll use it to derive the shared secret.
	sharedSecret2 := publicKey2.ECDH(privateKey1)

	// important note: you shouldn't use this shared secret
	// directly as an encryption key. you should first pass
	// it through a secure key derivation function (KDF).

	// this library does this for you if you call the DeriveKey
	// method in place of ECDH. the shared key is passed through
	// a secure KDF, returning a key safe to use for encryption.

	// these shared secrets will be the same.
	fmt.Println(bytes.Equal(sharedSecret1, sharedSecret2)) // true
}

func ExamplePublicKey_DeriveKey() {
	// PublicKey.DeriveKey(*PrivateKey) is the same as PrivateKey.DeriveKey(*PublicKey)

	// this is your key.
	privateKey1, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	publicKey1 := privateKey1.PublicKey

	// this key belongs to someone else.
	privateKey2, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	publicKey2 := privateKey2.PublicKey

	// the other person will send you their public key,
	// which you can use to derive the shared key.
	sharedKey1, err := publicKey1.DeriveKey(privateKey2)
	if err != nil {
		log.Fatal(err)
	}

	// likewise, you will send your public key to the other
	// person, and they'll use it to derive the shared key.
	sharedKey2, err := publicKey2.DeriveKey(privateKey1)
	if err != nil {
		log.Fatal(err)
	}

	// these keys are safe to use directly for encryption,
	// unlike the shared secret returned from ECDH, because
	// the library passes the shared ECDH secret through a
	// secure key derivation function (KDF) to make this key.

	// these shared keys will be the same.
	fmt.Println(bytes.Equal(sharedKey1, sharedKey2)) // true
}

func ExamplePublicKey_Equals() {
	privateKey, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.PublicKey

	// see PublicKey.Bytes() for more information.
	bytes := publicKey.Bytes(true)       // encrypt and store
	parsed, err := ParsePublicKey(bytes) // decrypt and parse
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(parsed.Equals(publicKey)) // true
}

func TestParsePublicKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pk := key.PublicKey

	// compressed
	parsed, err := ParsePublicKey(pk.Bytes(true))
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Equals(pk) {
		t.Fatal("key should equal itself after parsing (compressed)")
	}

	// uncompressed
	parsed, err = ParsePublicKey(pk.Bytes(false))
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Equals(pk) {
		t.Fatal("key should equal itself after parsing (uncompressed)")
	}
}

func TestPublicKey_Equals(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key2, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pk1 := key1.PublicKey
	pk2 := key2.PublicKey

	if !pk1.Equals(pk1) {
		t.Fatal("key should equal itself")
	}
	if pk1.Equals(pk2) {
		t.Fatal("key should not equal other key")
	}
}

func TestPublicKey_ECDH(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	key2, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	k1 := key1.ECDH(key2.PublicKey)
	k2 := key2.ECDH(key1.PublicKey)
	k3 := key1.PublicKey.ECDH(key2)
	k4 := key2.PublicKey.ECDH(key1)

	if !bytes.Equal(k1, k2) || !bytes.Equal(k2, k3) || !bytes.Equal(k3, k4) {
		t.Errorf("expected all ECDH derived keys to match")
	}
}

func TestPublicKey_DeriveKey(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	key2, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	k1, err := key1.DeriveKey(key2.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := key2.DeriveKey(key1.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k3, err := key1.PublicKey.DeriveKey(key2)
	if err != nil {
		t.Fatal(err)
	}
	k4, err := key2.PublicKey.DeriveKey(key1)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k1, k2) || !bytes.Equal(k2, k3) || !bytes.Equal(k3, k4) {
		t.Errorf("expected all ECDH/KDF derived keys to match")
	}
}
