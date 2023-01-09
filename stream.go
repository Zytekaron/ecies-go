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

// StreamBufferSize is the number of bytes to process at a time.
const StreamBufferSize = 4096

// StreamIVLength is the length of the IV used in AES-CTR.
const StreamIVLength = 16

// StreamHMACLength is the length of the MAC used in HMAC-SHA512.
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
	c, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	ctr := cipher.NewCTR(c, iv)

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
		// Propagate non-EOF errors.
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
	const bufSize = StreamBufferSize + StreamHMACLength

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
	// Create a new buffered reader from the input reader.
	// The trailing StreamHMACLength bytes are reserved
	// for the MAC, meaning they should not be assumed to
	// be data, in case the subsequent peek/read is empty.
	buf := bufio.NewReaderSize(in, bufSize)
	for {
		// Peek ahead up to the buffer size.
		peek, err := buf.Peek(bufSize)
		// If an error occurred, it should be propagated to
		// the caller. If the peeked slice does not contain
		// at least bufSize bytes, the end of reader has been
		// reached, and the MAC should be copied and verified.
		if err != nil {
			// Propagate non-EOF errors.
			if err != io.EOF {
				return err
			}

			// Handle trailing data; should be the MAC.
			left := buf.Buffered()
			if left < StreamHMACLength {
				return io.ErrUnexpectedEOF
			}

			// Save the MAC for verification later.
			mac = peek[left-StreamHMACLength : left]

			// If the amount of data remaining in the
			// slice is equivalent to the MAC length,
			// there is no more data to be decrypted
			// at the beginning of the slice.
			if left == StreamHMACLength {
				break
			}
		}

		// This slice represents the data portion,
		// cutting off the reserved MAC portion.
		data := peek[:len(peek)-StreamHMACLength]

		// Write the current data portion to HMAC.
		h.Write(data)

		// Perform decryption on the data portion.
		ctr.XORKeyStream(data, data)
		_, err = out.Write(data)
		if err != nil {
			return err
		}

		// Complete the read. This only reads data
		// which is known to be part of the message,
		// so if any part of the MAC was present in
		// the peek slice, the entirety of the MAC
		// will be available during the next peek.
		_, err = buf.Read(data)
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
