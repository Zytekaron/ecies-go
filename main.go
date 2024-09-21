package squad

import (
	"crypto/rand"
	"fmt"
)

// Split takes the secret and splits it into n shares,
// where at least k are required to recreate the secret.
//
// Shares are indexed in the map from 1 to n. When you
// combine shares, the key/value pairs must match, aside
// from omitting up to (n-k) key/value pairs. For example,
// you cannot swap the values for shares[1] and shares[3],
// as the key denotes x, and the value is the coefficient.
// shares[0] is not used, as this is where the secret lies.
//
// If your use case requires that it be possible to
// determine if the secret was properly recreated later,
// you should add information to the secret that allows
// you to test for garbage output. For example, you could
// make the first 8 bytes all zeros. The combination step
// is unaware of situations where < k shares are combined.
//
// Constraints:
//   - k <= n <= 255
//   - 2 <= k <= 255
//
// Reference: https://en.wikipedia.org/wiki/Shamir's_secret_sharing
func Split(secret []byte, n, k byte) (map[byte][]byte, error) {
	if k < 2 {
		panic("k must be at least 2")
	}
	if n < k {
		panic("n must not be less than k")
	}

	degree := k - 1

	shares := map[byte][]byte{}
	for i := byte(1); i <= n; i++ {
		shares[i] = make([]byte, len(secret))
	}

	for i := 0; i < len(secret); i++ {
		coefficients, err := makePolynomial(rand.Reader, secret[i], degree)
		if err != nil {
			return nil, fmt.Errorf("error generating polynomial: %w", err)
		}

		for x := byte(1); x <= n; x++ {
			y := evaluate(coefficients, x)
			shares[x][i] = y
		}
	}

	return shares, nil
}

// Combine takes the available shares and attempts
// to use them to recreate the original secret.
//
// At least k of the original shares must be present
// for this operation to succeed, otherwise it will
// silently fail by returning garbage output.
func Combine(shares map[byte][]byte) []byte {
	var secretLength int
	for _, share := range shares {
		secretLength = len(share)
		break
	}

	samples := make([]point, len(shares))
	secret := make([]byte, secretLength)
	for i := 0; i < secretLength; i++ {
		sampleIndex := 0
		for x := range shares {
			samples[sampleIndex] = point{x: x, y: shares[x][i]}
			sampleIndex++
		}

		secret[i] = interpolate(samples, 0)
	}

	return secret
}
