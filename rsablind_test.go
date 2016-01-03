package rsablind

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	"github.com/cryptoballot/fdh"
	"github.com/davecgh/go-spew/spew"
	"math/big"
	"testing"
)

func TestBlindSign(t *testing.T) {
	data := []byte("data")

	h := fdh.New(crypto.SHA256, 256)
	h.Write(data)
	hashed := h.Sum(nil)

	blindSignTest(t, "TestBlindSign", data)
}

func TestBlindSignBig(t *testing.T) {
	c := 546
	data := make([]byte, c)
	_, err := rand.Read(data)
	if err != nil {
		t.Error(err)
	}

	blindSignTest(t, "TestBlindSignBig", data)
}

func blindSignTest(t *testing.T, test string, data []byte) {
	h := fdh.New(crypto.SHA256, 256)
	h.Write(data)
	hashed := h.Sum(nil)

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

	pk := key.PublicKey.N
	ms := new(big.Int).SetBytes(hashed)
	spew.Dump(pk.BitLen())
	spew.Dump(ms.BitLen())
	if ms.Cmp(pk) == 1 {
		spew.Dump("will fail")
	}

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
