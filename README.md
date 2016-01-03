#RSA Blind
##RSA Blind Signing using a Full Domain Hash

This library implements a Full-Domain-Hash RSA Blind Signature Scheme. 

In cryptography, a blind signature is a form of digital signature in which the content of a message is disguised (blinded) before it is signed. The entity signing the message does not know the contents of the message being signed. 

### Caveats

1. **This library has not undergone a security review or audit and should not be used in production code.**

2. The key used to sign the blinded messages should not be used for any other purpose. Re-using this key in other contexts opens it up to attack. See 

3. Use the Full-Domain-Hash package (https://github.com/cryptoballot/fdh) to expand the size of your hash to a secure size. You should use a full-domain-hash size of at least 1024 bits. This hash size needs to remain significantly smaller than your key size to avoid RSA verification failures. A good rule of thumb is to use 2056 bit keys and 1024 bit hashes. 

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

	// We do a SHA256 full domain hash out to 1024 bits (half the key size)
	hashed := fdh.Sum(crypto.SHA256, keysize/2, message)

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
