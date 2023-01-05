package ecies

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

const ellipticText = "Hello, World!"

// used for examples
var publicKeyBytes, privateKeyBytes, ciphertext []byte

func ExampleEncryptSimple() {
	// parse a public key, or use a new
	// one generated using GenerateKey().
	publicKey, err := ParsePublicKey(publicKeyBytes)
	if err != nil {
		log.Fatal(err)
	}

	// encrypt data using the public key.
	ciphertext, err := EncryptSimple(publicKey, []byte("my secret string"))
	if err != nil {
		log.Fatal(err)
	}

	// send or store it. hex or base64 are good formats.
	fmt.Println(hex.EncodeToString(ciphertext))
}

func ExampleDecryptSimple() {
	// parse a private key, or use a new
	// one generated using GenerateKey().
	privateKey := ParsePrivateKey(publicKeyBytes)

	// decrypt data using the private key.
	plaintext, err := DecryptSimple(privateKey, ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	// send or saveFile the output.
	fmt.Println(string(plaintext))
}

func ExampleEncrypt() {
	// parse a public key, or use a new
	// one generated using GenerateKey().
	publicKey, err := ParsePublicKey(publicKeyBytes)
	if err != nil {
		log.Fatal(err)
	}

	// open file for encryption.
	input, err := os.Open("secret.txt")
	if err != nil {
		log.Fatal(err)
	}

	// open file for output.
	output, err := os.Create("secret.txt.enc")
	if err != nil {
		log.Fatal(err)
	}

	// encrypt secret.txt into secret.txt.enc using ecc public key.
	err = Encrypt(publicKey, input, output)
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleDecrypt() {
	// parse a private key, or use a new
	// one generated using GenerateKey().
	privateKey := ParsePrivateKey(privateKeyBytes)

	// open file for decryption.
	input, err := os.Open("secret.txt.enc")
	if err != nil {
		log.Fatal(err)
	}

	// open file for output.
	output, err := os.Create("secret.txt")
	if err != nil {
		log.Fatal(err)
	}

	// decrypt secret.txt.enc into secret.txt using ecc private key.
	err = Decrypt(privateKey, input, output)
	if err != nil {
		log.Fatal(err)
	}
}

func TestEllipticSimple(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal("generating ecc key:", err)
	}

	ciphertext, err := EncryptSimple(key.PublicKey, []byte(ellipticText))
	if err != nil {
		t.Fatal("encrypting:", err)
	}

	plaintext, err := DecryptSimple(key, ciphertext)
	if err != nil {
		t.Fatal("decrypting:", err)
	}

	if string(plaintext) != ellipticText {
		t.Fatal("expected decrypted text to match original")
	}
}

func TestElliptic(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal("generating ecc key:", err)
	}

	var ciphertextBuffer bytes.Buffer

	// encrypt stream.
	plaintextReader := strings.NewReader(ellipticText)
	err = Encrypt(key.PublicKey, plaintextReader, &ciphertextBuffer)
	if err != nil {
		t.Fatal("encrypting:", err)
	}

	// decrypt stream.
	var plaintextWriter bytes.Buffer
	err = Decrypt(key, &ciphertextBuffer, &plaintextWriter)
	if err != nil {
		t.Fatal("decrypting:", err)
	}

	// verify stream results.
	if string(plaintextWriter.Bytes()) != ellipticText {
		t.Fatal("expected decrypted text to match original")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		// encrypt stream
		plaintextReader := strings.NewReader(ellipticText)
		ciphertextWriter := &bytes.Buffer{}
		err := Encrypt(key.PublicKey, plaintextReader, ciphertextWriter)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}

	// encrypt stream
	plaintextReader := strings.NewReader(ellipticText)
	ciphertextWriter := &bytes.Buffer{}
	err = Encrypt(key.PublicKey, plaintextReader, ciphertextWriter)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		// decrypt stream
		ciphertextReader := bytes.NewBuffer(ciphertextWriter.Bytes()) // clone (only needed here)
		plaintextWriter := &bytes.Buffer{}
		err = Decrypt(key, ciphertextReader, plaintextWriter)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkElliptic(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}

	var ciphertextBuffer bytes.Buffer
	for i := 0; i < b.N; i++ {

		// encrypt stream
		plaintextReader := strings.NewReader(ellipticText)
		err := Encrypt(key.PublicKey, plaintextReader, &ciphertextBuffer)
		if err != nil {
			b.Fatal(err)
		}

		// decrypt stream
		plaintextWriter := &bytes.Buffer{}
		err = Decrypt(key, &ciphertextBuffer, plaintextWriter)
		if err != nil {
			b.Fatal(err)
		}

		// verify stream results.
		if string(plaintextWriter.Bytes()) != ellipticText {
			b.Fatal("expected decrypted text to match original")
		}
	}
}
