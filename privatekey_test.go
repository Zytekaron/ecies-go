package ecies

import (
	"bytes"
	"fmt"
	"log"
	"testing"
)

var saveFile func(string, any)

func ExampleGenerateKey() {
	privateKey, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	_ = privateKey.PublicKey // encapsulated public key
}

func ExampleParsePrivateKey() {
	privateKey, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// it's a good idea to encrypt this before saving it.
	bytes := privateKey.Bytes() // exported private key bytes

	privateKey = ParsePrivateKey(bytes) // same key as before
}

func ExamplePrivateKey_Bytes() {
	privateKey, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// it's a good idea to encrypt this before saving it.
	bytes := privateKey.Bytes()

	saveFile("myKey.sec", bytes)
}

func ExamplePrivateKey_ECDH() {
	// PrivateKey.ECDH(*PublicKey) is the same as PublicKey.ECDH(*PrivateKey)

	// this is your key.
	privateKey1, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// this key belongs to someone else.
	privateKey2, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// the other person will send you their public key, which
	// you can use to derive the shared secret using ECDH.
	sharedSecret1 := privateKey1.ECDH(privateKey2.PublicKey)

	// likewise, you will send your public key to the other
	// person, and they'll use it to derive the shared secret.
	sharedSecret2 := privateKey2.ECDH(privateKey1.PublicKey)

	// important note: you shouldn't use this shared secret
	// directly as an encryption key. you should first pass
	// it through a secure key derivation function (KDF).

	// this library does this for you if you call the DeriveKey
	// method in place of ECDH. the shared key is passed through
	// a secure KDF, returning a key safe to use for encryption.

	// these shared secrets will be the same.
	fmt.Println(bytes.Equal(sharedSecret1, sharedSecret2)) // true
}

func ExamplePrivateKey_DeriveKey() {
	// PrivateKey.DeriveKey(*PublicKey) is the same as PublicKey.DeriveKey(*PrivateKey)

	// this is your key.
	privateKey1, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// this key belongs to someone else.
	privateKey2, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// the other person will send you their public key,
	// which you can use to derive the shared key.
	sharedKey1, err := privateKey1.DeriveKey(privateKey2.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// likewise, you will send your public key to the other
	// person, and they'll use it to derive the shared key.
	sharedKey2, err := privateKey2.DeriveKey(privateKey1.PublicKey)
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

func ExamplePrivateKey_Equals() {
	privateKey, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	bytes := privateKey.Bytes()      // encrypt and store
	parsed := ParsePrivateKey(bytes) // decrypt and parse

	fmt.Println(parsed.Equals(privateKey)) // true
}

func TestGenerateKey(t *testing.T) {
	_, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
}

func TestParsePrivateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	parsed := ParsePrivateKey(key.Bytes())
	if !parsed.Equals(key) {
		t.Fatal("key should equal itself after parsing")
	}
}

func TestPrivateKey_Equals(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key2, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if !key1.Equals(key1) {
		t.Fatal("key should equal itself")
	}
	if key1.Equals(key2) {
		t.Fatal("key should not equal other key")
	}
}

func TestPrivateKey_ECDH(t *testing.T) {
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

func TestPrivateKey_DeriveKey(t *testing.T) {
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
