package rsablind

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"io"
	"math/big"
)

// Given the Public Key of the signing entity and a hashed message, blind the message so it cannot be inspected by the signing entity.
//
// Use the Full-Domain-Hash package (https://github.com/cryptoballot/fdh) to expand the size of your hash to a secure size. You should
// use a full-domain-hash size of at least 1024 bits, but bigger is better. However, this hash size needs to remain significantly
// smaller than your key size to avoid RSA verification failures. A good rule of thumb is to use 2048 bit keys and 1536 bit hashes,
// or 4096 bit keys and 3072 bit hashes (hash size is 3/4 the key size).
//
// This function returns the blinded message and an unblinding factor that can be used in conjuction with the `Unblind()` function to
// unblind the signature after the message has been signed.
func Blind(key *rsa.PublicKey, hashed []byte) (blindedData []byte, unblinder []byte, err error) {
	bitlen := key.N.BitLen()
	if len(hashed)*8 > bitlen {
		return nil, nil, rsa.ErrMessageTooLong
	}

	blinded, unblinderBig, err := blind(rand.Reader, key, new(big.Int).SetBytes(hashed))
	if err != nil {
		return nil, nil, err
	}

	return blinded.Bytes(), unblinderBig.Bytes(), nil
}

// Given a private key and a hashed message, blind sign the hashed message.
//
// The private key used here should not be used for any other purpose other than blind signing (use for other purposes is insecure
// when also using it for blind signatures)
func BlindSign(key *rsa.PrivateKey, hashed []byte) ([]byte, error) {
	bitlen := key.PublicKey.N.BitLen()
	if len(hashed)*8 > bitlen {
		return nil, rsa.ErrMessageTooLong
	}

	c := new(big.Int).SetBytes(hashed)
	m, err := decryptAndCheck(rand.Reader, key, c)
	if err != nil {
		return nil, err
	}

	return m.Bytes(), nil
}

// Given the Public Key of the signing entity, the blind signature, and the unblinding factor (obtained from `Blind()`), recover a new
// signature that will validate against the original hashed message.
func Unblind(pub *rsa.PublicKey, blindedSig, unblinder []byte) []byte {
	m := new(big.Int).SetBytes(blindedSig)
	unblinderBig := new(big.Int).SetBytes(unblinder)
	m.Mul(m, unblinderBig)
	m.Mod(m, pub.N)
	return m.Bytes()
}

// Verify that the unblinded signature properly signs the non-blinded (original) hashed message
func VerifyBlindSignature(pub *rsa.PublicKey, hashed, sig []byte) error {
	m := new(big.Int).SetBytes(hashed)
	bigSig := new(big.Int).SetBytes(sig)

	c := encrypt(new(big.Int), pub, bigSig)

	if subtle.ConstantTimeCompare(m.Bytes(), c.Bytes()) == 1 {
		return nil
	} else {
		return rsa.ErrVerification
	}
}

// Adapted from from crypto/rsa decrypt
func blind(random io.Reader, key *rsa.PublicKey, c *big.Int) (blinded, unblinder *big.Int, err error) {
	// Blinding enabled. Blinding involves multiplying c by r^e.
	// Then the decryption operation performs (m^e * r^e)^d mod n
	// which equals mr mod n. The factor of r can then be removed
	// by multiplying by the multiplicative inverse of r.

	var r *big.Int

	for {
		r, err = rand.Int(random, key.N)
		if err != nil {
			return
		}
		if r.Cmp(bigZero) == 0 {
			r = bigOne
		}
		ir, ok := modInverse(r, key.N)

		if ok {
			bigE := big.NewInt(int64(key.E))
			rpowe := new(big.Int).Exp(r, bigE, key.N)
			cCopy := new(big.Int).Set(c)
			cCopy.Mul(cCopy, rpowe)
			cCopy.Mod(cCopy, key.N)
			return cCopy, ir, nil
		}
	}
}
