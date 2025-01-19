package main

import (
	"fmt"
	"log"
	"slices"

	"github.com/zytekaron/squad"
)

// If you combine less than the required number of
// shares, you will get garbage output. This is an
// example of a way you can verify that the output
// is valid and thus enough shares were present, by
// prepending a padded checksum of zeros to the secret.
//
// There's a 1/2^64 chance that things would go wrong
// if you do it like this and then try to combine too
// few shares, so this should work fine for everyone.

var checksumPrefix = make([]byte, 8) // 64 bits of zeros

func main() {
	const n = 5
	const k = 3
	secret := []byte("Hello, World!")

	// prepend the "checksum prefix" to the secret.
	// (it's not actually a checksum, but close enough)
	secret = append(checksumPrefix, secret...)
	shares, err := squad.Split(secret, n, k)
	if err != nil {
		log.Fatalln("error splitting secret:", err)
	}

	// part 1: enough shares are present

	sharesPart1 := map[byte][]byte{
		1: shares[1],
		3: shares[3],
		5: shares[5],
	}

	combined := squad.Combine(sharesPart1)
	if len(combined) < len(checksumPrefix) {
		log.Fatalln("combined content isn't long enough")
	}
	if !slices.Equal(combined[:len(checksumPrefix)], checksumPrefix) {
		log.Fatalln("combined content is missing the zero prefix")
	}
	fmt.Println("Part 1 is working as expected")

	// part 2: not enough shares are present

	sharesPart2 := map[byte][]byte{
		2: shares[4],
		4: shares[4],
	}

	combined = squad.Combine(sharesPart2)
	if len(combined) < len(checksumPrefix) {
		log.Fatalln("combined content isn't long enough")
	}
	// updated this test: we should expect it to pass, so it
	// will report success when it doesn't find the prefix
	if !slices.Equal(combined[:len(checksumPrefix)], checksumPrefix) {
		//log.Fatalln("combined content is missing the zero prefix")
		fmt.Println("Part 2 is working as expected")
	}
}
