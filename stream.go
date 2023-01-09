package ecies

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
)

const StreamBufferSize = 4096
const StreamIVLength = 16
const StreamHMACLength = sha512.Size

var ErrInvalidMAC = errors.New("invalid mac")

// EncryptStreamSimple encrypts an arbitrary-length input stream
// using AES-256-CTR, and uses HMAC-SHA512 for authentication.
//
// The AES and HMAC keys are acquired from a KDF seeded with the provided secret.
func EncryptStreamSimple(in io.Reader, out io.Writer, secret []byte) error {
	aesKey, hmacKey, err := CryptoKDF(secret)
	if err != nil {
		return err
	}

	return EncryptStream(in, out, aesKey, hmacKey)
}

// DecryptStreamSimple decrypts an arbitrary-length input stream
// using AES-256-CTR, and uses HMAC-SHA512 for authentication.
//
// The AES and HMAC keys are acquired from a KDF seeded with the provided secret.
func DecryptStreamSimple(in io.Reader, out io.Writer, secret []byte) error {
	aesKey, hmacKey, err := CryptoKDF(secret)
	if err != nil {
		return err
	}

	return DecryptStream(in, out, aesKey, hmacKey)
}

// EncryptStream encrypts an arbitrary-length input stream
// using AES-CTR (bit size determined by the passed AES key),
// and uses HMAC-SHA512 with the passed key for authentication.
func EncryptStream(in io.Reader, out io.Writer, aesKey, hmacKey []byte) error {
	// Generate IV for encryption.
	iv := make([]byte, StreamIVLength)
	_, err := rand.Read(iv)
	if err != nil {
		return err
	}

	// Initialize AES-CTR cipher.
	aesCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	ctr := cipher.NewCTR(aesCipher, iv)

	// Initialize HMAC-SHA512.
	h := hmac.New(sha512.New, hmacKey)

	// Prepare for writing to both output stream and HMAC.
	mw := io.MultiWriter(out, h)

	// Write the IV to the output stream and HMAC.
	_, err = mw.Write(iv)
	if err != nil {
		return err
	}

	// Read and encrypt blocks from the input stream.
	buf := make([]byte, StreamBufferSize)
	for {
		// Read up to the buffer size from the input stream.
		n, err := in.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		// If there is data remaining, encrypt and
		// write it to the output stream and HMAC.
		if n > 0 {
			slice := buf[:n]
			ctr.XORKeyStream(slice, slice)
			_, err := mw.Write(slice)
			if err != nil {
				return err
			}
		}

		// If no data is remaining and got io.EOF, done.
		if err == io.EOF {
			break
		}
	}

	// Write the HMAC sum to the output stream.
	_, err = out.Write(h.Sum(nil))
	return err
}

// DecryptStream decrypts an arbitrary-length input stream
// using AES-CTR (bit size determined by the passed AES key),
// and uses HMAC-SHA512 with the passed key for authentication.
func DecryptStream(in io.Reader, out io.Writer, aesKey, hmacKey []byte) error {
	// Read IV from input stream.
	iv := make([]byte, StreamIVLength)
	_, err := io.ReadFull(in, iv)
	if err != nil {
		return err
	}

	// Initialize AES-CTR cipher.
	c, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	ctr := cipher.NewCTR(c, iv)

	// Initialize HMAC-SHA512.
	h := hmac.New(sha512.New, hmacKey)

	// Write the IV to the HMAC.
	h.Write(iv)

	// Read and decrypt blocks from the input stream.
	var mac []byte
	buf := bufio.NewReaderSize(in, StreamBufferSize)
	for {
		// Peek ahead up to the buffer size.
		b, err := buf.Peek(StreamBufferSize)
		if err != nil {
			if err != io.EOF {
				return err
			}

			// Handle trailing data; should be the MAC.
			left := buf.Buffered()
			if left < StreamHMACLength {
				return io.ErrUnexpectedEOF
			}

			// Save the MAC for comparison later.
			mac = b[left-StreamHMACLength : left]
			if left == StreamHMACLength {
				break
			}
		}

		// Write the current slice to HMAC.
		slice := b[:len(b)-StreamHMACLength]
		h.Write(slice)

		// Perform encryption
		ctr.XORKeyStream(slice, slice)
		_, err = out.Write(slice)
		if err != nil {
			return err
		}

		// Complete the read (previously only peeked).
		_, err = buf.Read(slice)
		if err != nil {
			return err
		}
	}

	// Ensure the MAC is valid.
	if !hmac.Equal(mac, h.Sum(nil)) {
		return ErrInvalidMAC
	}

	return nil
}
