package squad_test

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/zytekaron/squad"
)

var testRng = rand.NewChaCha8([32]byte{})

// TestSmall tests a basic input, combining exactly k shares.
func TestSmall(t *testing.T) {
	const n = 5
	const k = 3

	secret := []byte("Hello there, reader of my tests.")
	shares, err := squad.Split(secret, n, k)
	if err != nil {
		t.Fatal("error splitting:", err)
	}

	// n=5, k=3, len(shares)=3
	delete(shares, 2)
	delete(shares, 5)

	result := squad.Combine(shares)
	if !slices.Equal(result, secret) {
		t.Fatal("combined result does not match secret")
	}
}

// TestLarge tests a moderately larger input (8 KiB) with a larger threshold.
func TestLarge(t *testing.T) {
	const n = 100
	const k = 95

	secret := make([]byte, 8192)
	testRng.Read(secret)

	shares, err := squad.Split(secret, n, k)
	if err != nil {
		t.Fatal("error splitting:", err)
	}

	delete(shares, 3)
	delete(shares, 25)
	delete(shares, 41)
	delete(shares, 67)
	delete(shares, 97)

	result := squad.Combine(shares)
	if !slices.Equal(result, secret) {
		t.Fatal("combined result does not match secret")
	}
}

// TestFail tests combining k-1 shares to ensure the secret is irrevocable.
func TestFail(t *testing.T) {
	const n = 5
	const k = 3

	secret := []byte("Hello there, reader of my tests.")
	shares, err := squad.Split(secret, n, k)
	if err != nil {
		t.Fatal("error splitting:", err)
	}

	// n=5, k=3, len(shares)=2
	delete(shares, 2)
	delete(shares, 4)
	delete(shares, 5)

	result := squad.Combine(shares)
	if slices.Equal(result, secret) {
		t.Fatal("combined result should not match secret")
	}
}

// TestIntegrity is designed to test for rare discrepancies due to
// randomized byte values, galois field exp/log table errors, etc.
//
// If this test passes, everything should be in good working order.
func TestIntegrity(t *testing.T) {
	const n = 10
	const k = 5

	secret := make([]byte, 256)
	for i := 0; i < 1_000; i++ {
		testRng.Read(secret)

		shares, err := squad.Split(secret, n, k)
		if err != nil {
			t.Fatal("error splitting:", err)
		}

		delete(shares, 2)
		delete(shares, 5)
		delete(shares, 8)

		result := squad.Combine(shares)
		if !slices.Equal(result, secret) {
			t.Fatal("combined result does not match secret")
		}
	}
}

func ExampleSplit() {
	const n = 5
	const k = 3
	secret := []byte("Hello World!")

	shares, err := squad.Split(secret, n, k)
	if err != nil {
		log.Fatalln("error splitting secret:", err)
	}

	for x, share := range shares {
		fmt.Println(x, "=>", hex.EncodeToString(share))
	}
}

func ExampleCombine() {
	// 3 of the 5 shares from ExampleSplit
	shares := map[byte][]byte{
		2: {0xC2, 0x97, 0x73, 0xB4, 0xBF, 0x88, 0xDC, 0x0E, 0x4B, 0x81, 0x94, 0xEF},
		4: {0x0B, 0xBF, 0xB2, 0xBC, 0x6F, 0x9F, 0xB3, 0xC0, 0xA3, 0x97, 0x76, 0xFC},
		5: {0xCA, 0xA7, 0x2C, 0xFC, 0x33, 0x58, 0x8E, 0x15, 0x05, 0xA0, 0xFB, 0x5B},
	}

	result := squad.Combine(shares)
	fmt.Println(string(result)) // Hello, World!
}
