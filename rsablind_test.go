package rsablind

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	"math/big"
	"testing"

	"github.com/cryptoballot/fdh"
)

func TestBlindSign(t *testing.T) {
	data := []byte("data")

	hashed := fdh.Sum(crypto.SHA256, 256, data)

	key, _ := rsa.GenerateKey(rand.Reader, 512)
	// Do it twice to make sure we are also testing using cached precomputed values.
	blindSignTest(t, "TestBlindSign", hashed, key)
	blindSignTest(t, "TestBlindSign", hashed, key)
}

func TestBlindSignBig(t *testing.T) {
	c := 2048
	data := make([]byte, c)
	_, err := rand.Read(data)
	if err != nil {
		t.Error(err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 512)

	// Do it twice to make sure we are also testing using cached precomputed values.
	blindSignTest(t, "TestBlindSignBig", data, key)
	blindSignTest(t, "TestBlindSignBig", data, key)
}

func blindSignTest(t *testing.T, test string, data []byte, key *rsa.PrivateKey) {
	hashed := fdh.Sum(crypto.SHA256, 256, data)

	blinded, unblinder, err := Blind(&key.PublicKey, hashed)
	if err != nil {
		t.Error(err)
	}

	sig, err := BlindSign(key, blinded)
	if err != nil {
		t.Error(err)
	}
	unblindSig := Unblind(&key.PublicKey, sig, unblinder)

	// Check to make sure both the blinded and unblided data can be verified with the same signature
	if err := VerifyBlindSignature(&key.PublicKey, hashed, unblindSig); err != nil {
		t.Errorf(test+": Failed to verify for unblinded signature: %v", err)
	}
	if err := VerifyBlindSignature(&key.PublicKey, blinded, sig); err != nil {
		t.Errorf(test+": Failed to verify for blinded signature: %v", err)
	}

	// Check to make sure blind signing does not work when mismatched
	if err := VerifyBlindSignature(&key.PublicKey, data, sig); err == nil {
		t.Errorf(test + ": Faulty Verification for mismatched signature 1")
	}
	if err := VerifyBlindSignature(&key.PublicKey, blinded, unblindSig); err == nil {
		t.Errorf(test + ": Faulty Verification for mismatched signature 2")
	}
}

func TestErrors(t *testing.T) {
	hashed := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	// Generate a tiny key and make sure using it to blind results in errors
	key, _ := rsa.GenerateKey(rand.Reader, 128)

	_, _, err := Blind(&key.PublicKey, hashed)
	if err == nil {
		t.Error("Failed to get error on too large a hash")
	}
	_, err = BlindSign(key, hashed)
	if err == nil {
		t.Error("Failed to get error on too large a hash")
	}

	badkey := &rsa.PrivateKey{
		PublicKey: key.PublicKey,
		D:         big.NewInt(8),
		Primes:    []*big.Int{big.NewInt(12)},
	}
	_, err = BlindSign(badkey, []byte("ABC123"))
	if err == nil {
		t.Error("Failed to get error on bad private key")
	}

}
