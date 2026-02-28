package chilldkg

import (
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func HostPubkeyGen(hostseckey *ristretto.Scalar) *ristretto.Element {
	var pub ristretto.Element
	pub.ScalarBaseMult(hostseckey)
	return &pub
}

func HostSeckeyFromBytes(b []byte) (*ristretto.Scalar, error) {
	if len(b) != 32 {
		return nil, ErrInvalidHostSeckey
	}
	var s ristretto.Scalar
	if _, err := s.SetCanonicalBytes(b); err != nil {
		return nil, ErrInvalidHostSeckey
	}
	if s.Equal(ristretto.NewScalar()) == 1 {
		return nil, ErrInvalidHostSeckey
	}
	return &s, nil
}
