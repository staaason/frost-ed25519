package roast

import (
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type Session struct {
	ID        uint32
	SignerSet party.IDSlice

	PreShares      map[party.ID]*PreSignatureShare
	BindingFactors map[party.ID]*ristretto.Scalar
	NonceShares    map[party.ID]*ristretto.Element
	AggregateNonce ristretto.Element
	Challenge      ristretto.Scalar

	SigShares map[party.ID]*ristretto.Scalar
}

func NewSession(id uint32, signerSet party.IDSlice, preShares map[party.ID]*PreSignatureShare, pk *eddsa.Public, message []byte) *Session {
	bindingFactors := ComputeBindingFactors(signerSet, preShares, message)
	nonceShares, aggregateNonce := ComputeNonceCommitments(signerSet, preShares, bindingFactors)
	challenge := eddsa.ComputeChallenge(aggregateNonce, pk.GroupKey, message)

	return &Session{
		ID:             id,
		SignerSet:      signerSet,
		PreShares:      preShares,
		BindingFactors: bindingFactors,
		NonceShares:    nonceShares,
		AggregateNonce: *aggregateNonce,
		Challenge:      *challenge,
		SigShares:      make(map[party.ID]*ristretto.Scalar),
	}
}

func (s *Session) ValidateAndStore(pk *eddsa.Public, signerID party.ID, sigShare *ristretto.Scalar) bool {
	nonceShare, ok := s.NonceShares[signerID]
	if !ok {
		return false
	}

	if !ShareVal(pk, s.SignerSet, signerID, &s.AggregateNonce, nonceShare, &s.Challenge, sigShare) {
		return false
	}

	s.SigShares[signerID] = sigShare
	return true
}

func (s *Session) IsComplete(t int) bool {
	return len(s.SigShares) == t
}
