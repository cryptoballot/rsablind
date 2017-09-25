# RSA Blind

## RSA Blind Signing using a Full Domain Hash

[![Build Status](https://scrutinizer-ci.com/g/cryptoballot/rsablind/badges/build.png?b=master)](https://scrutinizer-ci.com/g/cryptoballot/rsablind/build-status/master)
[![Build Status](https://travis-ci.org/cryptoballot/rsablind.svg?branch=master)](https://travis-ci.org/cryptoballot/rsablind)
[![Go Report Card](https://goreportcard.com/badge/github.com/cryptoballot/rsablind)](https://goreportcard.com/report/github.com/cryptoballot/rsablind)
[![Coverage Status](https://coveralls.io/repos/github/cryptoballot/rsablind/badge.svg?branch=master)](https://coveralls.io/github/cryptoballot/rsablind?branch=master)
[![Scrutinizer Issues](https://img.shields.io/badge/scrutinizer-issues-blue.svg)](https://scrutinizer-ci.com/g/cryptoballot/rsablind/issues)
[![GoDoc](https://godoc.org/github.com/cryptoballot/rsablind?status.svg)](https://godoc.org/github.com/cryptoballot/rsablind)  

This library implements a Full-Domain-Hash RSA Blind Signature Scheme. 

In cryptography, a blind signature is a form of digital signature in which the content of a message is disguised (blinded) before it is signed. The entity signing the message does not know the contents of the message being signed. 

### Caveats

1. **This library has not undergone a security review or audit and should not be used in production code.**

2. The key used to sign the blinded messages should not be used for any other purpose. Re-using this key in other contexts opens it up to attack. 

3. Use the Full-Domain-Hash package (https://github.com/cryptoballot/fdh) to expand the size of your hash to a secure size. You should use a full-domain-hash size of at least 1024 bits, but bigger is better. However, this hash size needs to remain significantly smaller than your key size to avoid RSA verification failures. A good rule of thumb is to use 2048 bit keys and 1536 bit hashes, or 4096 bit keys and 3072 bit hashes (hash size is 3/4 the key size). 

4. Because we use a full-domain hash size that is less than the key size, this scheme is theoretically open to an Index Calculation Attack (see http://www.jscoron.fr/publications/isodcc.pdf). However, with a large enough RSA key (recommended 2048 bits or larger), and a large enough full-domain-hash (1024 bits or larger) this attack in infeasable. 

### Example
```go
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	"fmt"
	"github.com/cryptoballot/fdh"
	"github.com/cryptoballot/rsablind"
)

func main() {
	message := []byte("ATTACKATDAWN")

	keysize := 2048
	hashize := 1536

	// We do a SHA256 full-domain-hash expanded to 1536 bits (3/4 the key size)
	hashed := fdh.Sum(crypto.SHA256, hashize, message)

	// Generate a key
	key, _ := rsa.GenerateKey(rand.Reader, keysize)

	// Blind the hashed message
	blinded, unblinder, err := rsablind.Blind(&key.PublicKey, hashed)
	if err != nil {
		panic(err)
	}

	// Blind sign the blinded message
	sig, err := rsablind.BlindSign(key, blinded)
	if err != nil {
		panic(err)
	}

	// Unblind the signature
	unblindedSig := rsablind.Unblind(&key.PublicKey, sig, unblinder)

	// Verify the original hashed message against the unblinded signature
	if err := rsablind.VerifyBlindSignature(&key.PublicKey, hashed, unblindedSig); err != nil {
		panic("failed to verify signature")
	} else {
		fmt.Println("ALL IS WELL")
	}
}


```
