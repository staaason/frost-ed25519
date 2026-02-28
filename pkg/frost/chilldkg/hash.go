package chilldkg

import (
	"crypto/sha512"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

const dkgTag = "FROST-Ed25519/ChillDKG/"

func taggedHash(tag string, data ...[]byte) []byte {
	prefix := []byte(dkgTag + tag)
	h := sha512.New()
	_, _ = h.Write(prefix)
	for _, d := range data {
		_, _ = h.Write(d)
	}
	out := h.Sum(nil)
	return out[:32]
}

func taggedHashScalar(tag string, data ...[]byte) *ristretto.Scalar {
	prefix := []byte(dkgTag + tag)
	h := sha512.New()
	_, _ = h.Write(prefix)
	for _, d := range data {
		_, _ = h.Write(d)
	}
	buf := h.Sum(nil)
	var s ristretto.Scalar
	_, _ = s.SetUniformBytes(buf)
	return &s
}
