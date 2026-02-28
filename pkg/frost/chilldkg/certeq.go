package chilldkg

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

const certeqSigSize = 64

func certeqMessage(eqInput []byte, idx int) []byte {
	prefix := []byte(dkgTag + "certeq message")
	for len(prefix) < 33 {
		prefix = append(prefix, 0x00)
	}
	idxBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBytes, uint32(idx))
	return append(prefix, append(idxBytes, eqInput...)...)
}

func certeqSign(hostseckey *ristretto.Scalar, hostpubkey *ristretto.Element, idx int, eqInput []byte) []byte {
	msg := certeqMessage(eqInput, idx)
	return schnorrSign(hostseckey, hostpubkey, msg)
}

func certeqVerify(hostpubkeys []ristretto.Element, eqInput []byte, cert []byte) error {
	n := len(hostpubkeys)
	if len(cert) != n*certeqSigSize {
		return fmt.Errorf("%w: invalid certificate length", ErrInvalidCertificate)
	}
	for i := 0; i < n; i++ {
		msg := certeqMessage(eqInput, i)
		sig := cert[i*certeqSigSize : (i+1)*certeqSigSize]
		if !schnorrVerify(&hostpubkeys[i], msg, sig) {
			return &FaultyParticipantError{
				Index: i,
				Msg:   fmt.Sprintf("chilldkg: invalid certificate signature from participant %d", i),
			}
		}
	}
	return nil
}

func certeqCertLen(n int) int {
	return n * certeqSigSize
}

func schnorrSign(seckey *ristretto.Scalar, pubkey *ristretto.Element, msg []byte) []byte {
	kHash := sha512.New()
	_, _ = kHash.Write([]byte(dkgTag + "schnorr nonce"))
	_, _ = kHash.Write(seckey.Bytes())
	_, _ = kHash.Write(msg)
	kBuf := kHash.Sum(nil)
	var k ristretto.Scalar
	_, _ = k.SetUniformBytes(kBuf)

	var R ristretto.Element
	R.ScalarBaseMult(&k)

	challenge := schnorrChallenge(&R, pubkey, msg)

	var s ristretto.Scalar
	s.MultiplyAdd(seckey, challenge, &k)

	sig := make([]byte, 0, 64)
	sig = append(sig, R.Bytes()...)
	sig = append(sig, s.Bytes()...)
	return sig
}

func schnorrVerify(pubkey *ristretto.Element, msg []byte, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	var R ristretto.Element
	if _, err := R.SetCanonicalBytes(sig[:32]); err != nil {
		return false
	}
	var s ristretto.Scalar
	if _, err := s.SetCanonicalBytes(sig[32:]); err != nil {
		return false
	}

	challenge := schnorrChallenge(&R, pubkey, msg)

	var pubNeg ristretto.Element
	pubNeg.Negate(pubkey)
	var RPrime ristretto.Element
	RPrime.VarTimeDoubleScalarBaseMult(challenge, &pubNeg, &s)

	return RPrime.Equal(&R) == 1
}

func schnorrChallenge(R, pubkey *ristretto.Element, msg []byte) *ristretto.Scalar {
	h := sha512.New()
	_, _ = h.Write([]byte(dkgTag + "schnorr challenge"))
	_, _ = h.Write(R.Bytes())
	_, _ = h.Write(pubkey.Bytes())
	_, _ = h.Write(msg)
	buf := h.Sum(nil)
	var c ristretto.Scalar
	_, _ = c.SetUniformBytes(buf)
	return &c
}
