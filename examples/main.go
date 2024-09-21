package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/zytekaron/squad"
)

func main() {
	const n = 5
	const k = 3
	secret := []byte("Hello World!")

	// split your secret into n shares, where at least
	// k of them are required to recover the secret
	shares, err := squad.Split(secret, n, k)
	if err != nil {
		log.Fatalln("error splitting secret:", err)
	}

	// take a look at the shares!
	for x := byte(1); x <= 5; x++ { // x = 1 to n
		fmt.Println(x, "=>", hex.EncodeToString(shares[x]))
	}

	// provide at least k(3) of the original n(5)
	// shares to successfully recover the secret
	shares = map[byte][]byte{
		1: shares[1],
		3: shares[3],
		5: shares[5],
	}

	// combine the shares and you have your secret!
	result := squad.Combine(shares)
	fmt.Println(string(result)) // Hello, World!
}
