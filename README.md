# ecies-go
**version:** v0.0.0

## Installation
```
go get github.com/zytekaron/go-ecies
```
No release has been published yet, so if you want to download
this library to test, you'll need to target a specific commit
([see go docs: "Managing Dependencies"](https://go.dev/doc/modules/managing-dependencies))

## Warnings
- No cryptographic security guarantees!!!
- No continued development guarantees
- No API stability guarantees

Basically, don't use this library in anything but a
testing project until I get it up to speed and it gets
some stringent security auditing, which will probably
never happen. Anything before a v1.0.0 release is to
be considered highly unstable, buggy, dangerous, and
all in all a *really* bad idea to use in production.

https://github.com/ecies is a good ECIES library suite
you can use, including in Go; you just can't run it on
arbitrary-length streams of data (if it doesn't fit in
memory, you're forced to break up the message manually.)

## Implementation Details
- Uses the P-521 elliptic curve (subject to change)
- AES-256-CTR / HMAC-SHA512 for stream encryption and MAC
- HKDF-SHA512 for key derivation from ECDH shared secret

## Primary Sources
- [./elliptic.go](./elliptic.go) - ECIES implementation (ECC key management for encryption)
- [./privatekey.go](./privatekey.go) - PrivateKey implementation (*currently* uses P-521)
- [./publickey.go](./publickey.go) - PublicKey implementation
- [./stream.go](./stream.go) - AES-256-CTR / HMAC-SHA512 stream encryption implementation
- [./utils.go](./utils.go) - KDF functions

# License
**ecies-go** is licensed under the [MIT License](./LICENSE)
