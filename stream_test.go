package ecies

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

const streamText = "Hello, World!"
const streamKey = "password123"

func TestStreamsSimple(t *testing.T) {
	var ciphertextBuffer bytes.Buffer

	// encrypt stream.
	plaintextReader := strings.NewReader(streamText)
	err := EncryptStreamSimple(plaintextReader, &ciphertextBuffer, []byte(streamKey))
	if err != nil {
		t.Fatal(err)
	}

	// decrypt stream.
	var plaintextWriter bytes.Buffer
	err = DecryptStreamSimple(&ciphertextBuffer, &plaintextWriter, []byte(streamKey))
	if err != nil {
		t.Fatal(err)
	}

	// verify stream results.
	if string(plaintextWriter.Bytes()) != streamText {
		t.Fatal("expected decrypted text to match original")
	}
}

func TestStreams(t *testing.T) {
	// generate temporary AES/HMAC keys.
	aesKey := make([]byte, 32)
	_, err := rand.Read(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	if err != nil {
		t.Fatal(err)
	}

	var ciphertextBuffer bytes.Buffer

	// encrypt stream.
	plaintextReader := strings.NewReader(streamText)
	err = EncryptStream(plaintextReader, &ciphertextBuffer, aesKey, hmacKey)
	if err != nil {
		t.Fatal(err)
	}

	// decrypt stream.
	var plaintextWriter bytes.Buffer
	err = DecryptStream(&ciphertextBuffer, &plaintextWriter, aesKey, hmacKey)
	if err != nil {
		t.Fatal(err)
	}

	// verify stream results.
	if string(plaintextWriter.Bytes()) != streamText {
		t.Fatal("expected decrypted text to match original")
	}
}
