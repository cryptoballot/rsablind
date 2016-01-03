package rsablind

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
)

var ErrMessageWrongSize = errors.New("rsablind: hashed message is incorrect size")

func BlindSign(key *rsa.PrivateKey, hashed []byte) ([]byte, error) {
	bitlen := key.PublicKey.N.BitLen()
	if bitlen != len(hashed) * 8 {
		return nil, ErrMessageWrongSize
	}

	c := new(big.Int).SetBytes(hashed)
	m, err := decrypt(rand.Reader, key, c)
	if err != nil {
		return nil, err
	}

	return m.Bytes(), nil
}

func Blind(key *rsa.PublicKey, hashed []byte) (blindedData []byte, unblinder []byte, err error) {
	bitlen := key.N.BitLen()
	if bitlen != len(hashed) * 8 {
		return nil, nil, ErrMessageWrongSize
	}

	blinded, unblinderBig, err := blind(rand.Reader, key, new(big.Int).SetBytes(hashed))
	if err != nil {
		return nil, nil, err
	}

	return blinded.Bytes(), unblinderBig.Bytes(), nil
}

func Unblind(key *rsa.PublicKey, blindedSig, unblinder []byte) []byte {
	m := new(big.Int).SetBytes(blindedSig)
	unblinderBig := new(big.Int).SetBytes(unblinder)
	m.Mul(m, unblinderBig)
	m.Mod(m, key.N)
	return m.Bytes()
}

func VerifyBlindSignature(key *rsa.PublicKey, hashed, sig []byte) error {
	m := new(big.Int).SetBytes(hashed)
	bigSig := new(big.Int).SetBytes(sig)
	



	c := encrypt(bigZero, key, bigSig)
	if m.Cmp(c) != 0 {
		return rsa.ErrVerification
	} else {
		return nil
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



// All variables and functions below are carbon copy-paste from the standard library crypto/rsa

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// Carbon copy of crypto/rsa encrypt()
func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

// Carbon copy of crypto/rsa decrypt()
// decrypt performs an RSA decryption, resulting in a plaintext integer. If a
// random source is given, RSA blinding is used.
func decrypt(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	// TODO(agl): can we get away with reusing blinds?
	if c.Cmp(priv.N) > 0 {
		err = rsa.ErrDecryption
		return
	}

	var ir *big.Int
	if random != nil {
		// Blinding enabled. Blinding involves multiplying c by r^e.
		// Then the decryption operation performs (m^e * r^e)^d mod n
		// which equals mr mod n. The factor of r can then be removed
		// by multiplying by the multiplicative inverse of r.

		var r *big.Int

		for {
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			var ok bool
			ir, ok = modInverse(r, priv.N)
			if ok {
				break
			}
		}
		bigE := big.NewInt(int64(priv.E))
		rpowe := new(big.Int).Exp(r, bigE, priv.N)
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}

	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}

	if ir != nil {
		// Unblind.
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}

// Carbon-copy of crypto/rsa decryptAndCheck()
func decryptAndCheck(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	m, err = decrypt(random, priv, c)
	if err != nil {
		return nil, err
	}

	// In order to defend against errors in the CRT computation, m^e is
	// calculated, which should match the original ciphertext.
	check := encrypt(new(big.Int), &priv.PublicKey, m)
	if c.Cmp(check) != 0 {
		return nil, errors.New("rsa: internal error")
	}
	return m, nil
}

// Carbon-copy of crypto/rsa modInverse()
// modInverse returns ia, the inverse of a in the multiplicative group of prime
// order n. It requires that a be a member of the group (i.e. less than n).
func modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigOne) != 0 {
		// In this case, a and n aren't coprime and we cannot calculate
		// the inverse. This happens because the values of n are nearly
		// prime (being the product of two primes) rather than truly
		// prime.
		return
	}

	if x.Cmp(bigOne) < 0 {
		// 0 is not the multiplicative inverse of any element so, if x
		// < 1, then x is negative.
		x.Add(x, n)
	}

	return x, true
}