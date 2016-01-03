// Example:
//
//   package main
//
//   import (
//   	"crypto"
//   	"crypto/rand"
//   	"crypto/rsa"
//   	_ "crypto/sha256"
//   	"fmt"
//   	"github.com/cryptoballot/fdh"
//   	"github.com/cryptoballot/rsablind"
//   )
//
//   func main() {
//   	message := []byte("ATTACKATDAWN")
//
//   	keysize := 2048
//   	hashize := 1536
//
//   	// We do a SHA256 full-domain-hash expanded to 1536 bits (3/4 the key size)
//   	hashed := fdh.Sum(crypto.SHA256, hashize, message)
//
//   	// Generate a key
//   	key, _ := rsa.GenerateKey(rand.Reader, keysize)
//
//   	// Blind the hashed message
//   	blinded, unblinder, err := rsablind.Blind(&key.PublicKey, hashed)
//   	if err != nil {
//   		panic(err)
//   	}
//
//   	// Blind sign the blinded message
//   	sig, err := rsablind.BlindSign(key, blinded)
//   	if err != nil {
//   		panic(err)
//   	}
//
//   	// Unblind the signature
//   	unblindedSig := rsablind.Unblind(&key.PublicKey, sig, unblinder)
//
//   	// Verify the original hashed message against the unblinded signature
//   	if err := rsablind.VerifyBlindSignature(&key.PublicKey, hashed, unblindedSig); err != nil {
//   		panic("failed to verify signature")
//   	} else {
//   		fmt.Println("ALL IS WELL")
//   	}
//   }
package rsablind
