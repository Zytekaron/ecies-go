# Squad
**version:** 0.1

Shamir Secret Sharing System implementation in Go.

Considerations:
- Standard Shamir Secret Sharing Scheme Settings: `n` keys, `k` threshold
- Usage as a command-line app to split text and files
- Usage as a Go package to split arbitrary byte slices

Non-considerations:
- Large files / `io.Reader` and `io.Writer`: If you need to split
  large files, consider encrypting the file using a fast symmetric
  algorithm like AES-256 or XChaCha20, then splitting the key.
  This will save on storage for each share *and* recovery speed.
- Side-channel attacks: If the secret is important, the system you
  run this on should already be trusted (since it contains plaintext
  secrets), so side-channel attacks should be essentially a non-factor.

# Usage

## Command-line

```shell
# Split the provided text into 3 parts, with a threshold of 2
squad split "Hello, World!" -n 3 -k 2

# Split input.txt into 10 parts with a threshold of 7,
# using "squad_out_" as the prefix for the name.
squad split -f "input.txt" -n 10 -k 7 -o "squad_out_"

# Generate a new random key, print it to the console,
# and split it into 5 parts with a threshold of 3.
# You can use the printed key to encrypt data eg using
# AES, and the key is recoverable with at least 3 shares.
openssl rand -base16 32 | tee /dev/tty | squad split -n 5 -k 3

# More options:
# - Use {i} indices (starting with 1) to place the
#   the share number in the start/middle of the name.
#   Share numbers are NOT extracted from file name or
#   sorting order; they are stored in the first byte
#   of the contents. File names do not matter.
squad split ... -o "squad_out_{i}.txt"
```

```shell
# Combine all of the share files and print the
# recovered secret directly to the console.
squad combine "squad_out_"*

# Combine all of the share files into an output file.
squad combine "squad_out_"* -o recovered.txt
```

## Go package

# License
**squad** is licensed under the [MIT License](./LICENSE).
