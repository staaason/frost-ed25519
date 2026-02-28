package roast

import (
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type Signer struct {
	id      party.ID
	secret  *eddsa.SecretShare
	pk      *eddsa.Public
	message []byte

	nonceState *NonceState
}

func NewSigner(secret *eddsa.SecretShare, pk *eddsa.Public, message []byte) *Signer {
	return &Signer{
		id:      secret.ID,
		secret:  secret,
		pk:      pk,
		message: message,
	}
}

func (s *Signer) Init() *PreSignatureShare {
	state, share := PreRound()
	s.nonceState = state
	return share
}

func (s *Signer) ID() party.ID {
	return s.id
}

func (s *Signer) Sign(signerSet party.IDSlice, preShares map[party.ID]*PreSignatureShare) (*ristretto.Scalar, *PreSignatureShare, error) {
	sigShare, err := SignRound(s.secret, s.pk, signerSet, s.nonceState, preShares, s.message)
	if err != nil {
		return nil, nil, err
	}

	nextState, nextShare := PreRound()
	s.nonceState = nextState

	return sigShare, nextShare, nil
}
