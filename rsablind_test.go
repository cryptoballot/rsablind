package rsablind

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	"github.com/cryptoballot/fdh"
	"testing"
)

func TestBlindSign(t *testing.T) {
	data := []byte("data")

	hashed := fdh.Sum(crypto.SHA256, 256, data)

	blindSignTest(t, "TestBlindSign", hashed)
}

func TestBlindSignBig(t *testing.T) {
	c := 2048
	data := make([]byte, c)
	_, err := rand.Read(data)
	if err != nil {
		t.Error(err)
	}

	blindSignTest(t, "TestBlindSignBig", data)
}

func blindSignTest(t *testing.T, test string, data []byte) {
	hashed := fdh.Sum(crypto.SHA256, 256, data)

	key, _ := rsa.GenerateKey(rand.Reader, 512)
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
		t.Errorf(test + ": Faulty Verfication for mismatched signature 1")
	}
	if err := VerifyBlindSignature(&key.PublicKey, blinded, unblindSig); err == nil {
		t.Errorf(test + ": Faulty Verfication for mismatched signature 2")
	}
}
