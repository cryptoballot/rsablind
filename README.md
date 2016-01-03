
#RSA Blind: RSA Blind Signing using a Full Domain Hash


Because we use a full-domain hash that is sized at half the number of RSA bits, this approach is theoretically open to an Index Calculation Attack (see http://www.jscoron.fr/publications/isodcc.pdf). However, with a large enough RSA key (recommended 2048 bits or larger), this attack in infeasable. RSA key sizes under 2048 are absolutly not recommended.

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
        h := fdh.New(crypto.SHA256, keysize/2)
        h.Write(message)
        hashed := h.Sum(nil)

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
        unblindSig := rsablind.Unblind(&key.PublicKey, sig, unblinder)

        // Verify the original hashed message against the unblinded signature
        if err := rsablind.VerifyBlindSignature(&key.PublicKey, hashed, unblindSig); err != nil {
                panic("failed to verify signature")
        } else {
                fmt.Println("ALL IS WELL")
        }
}

```
