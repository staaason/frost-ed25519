package roast

import (
	"crypto/sha512"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

var hashDomainSeparation = []byte("FROST-SHA512")

func PreRound() (*NonceState, *PreSignatureShare) {
	var state NonceState
	var share PreSignatureShare

	scalar.SetScalarRandom(&state.D)
	share.Di.ScalarBaseMult(&state.D)

	scalar.SetScalarRandom(&state.E)
	share.Ei.ScalarBaseMult(&state.E)

	return &state, &share
}

func ComputeBindingFactors(signerSet party.IDSlice, preShares map[party.ID]*PreSignatureShare, message []byte) map[party.ID]*ristretto.Scalar {
	messageHash := sha512.Sum512(message)

	sizeB := int(signerSet.N()) * (party.IDByteSize + 32 + 32)
	bufferHeader := len(hashDomainSeparation) + party.IDByteSize + len(messageHash)
	sizeBuffer := bufferHeader + sizeB
	offsetID := len(hashDomainSeparation)

	buffer := make([]byte, 0, sizeBuffer)
	buffer = append(buffer, hashDomainSeparation...)
	buffer = append(buffer, signerSet[0].Bytes()...)
	buffer = append(buffer, messageHash[:]...)

	for _, id := range signerSet {
		ps := preShares[id]
		buffer = append(buffer, id.Bytes()...)
		buffer = append(buffer, ps.Di.Bytes()...)
		buffer = append(buffer, ps.Ei.Bytes()...)
	}

	factors := make(map[party.ID]*ristretto.Scalar, len(signerSet))
	for _, id := range signerSet {
		copy(buffer[offsetID:], id.Bytes())
		digest := sha512.Sum512(buffer)
		var s ristretto.Scalar
		_, _ = s.SetUniformBytes(digest[:])
		factors[id] = &s
	}

	return factors
}

func ComputeNonceCommitments(signerSet party.IDSlice, preShares map[party.ID]*PreSignatureShare, bindingFactors map[party.ID]*ristretto.Scalar) (nonceShares map[party.ID]*ristretto.Element, aggregateNonce *ristretto.Element) {
	nonceShares = make(map[party.ID]*ristretto.Element, len(signerSet))
	aggregateNonce = ristretto.NewIdentityElement()

	for _, id := range signerSet {
		ps := preShares[id]
		rho := bindingFactors[id]

		var ri ristretto.Element
		ri.ScalarMult(rho, &ps.Ei)
		ri.Add(&ri, &ps.Di)

		nonceShares[id] = &ri
		aggregateNonce.Add(aggregateNonce, &ri)
	}

	return nonceShares, aggregateNonce
}

func ShareVal(pk *eddsa.Public, signerSet party.IDSlice, signerID party.ID, aggregateNonce *ristretto.Element, nonceShare *ristretto.Element, challenge *ristretto.Scalar, sigShare *ristretto.Scalar) bool {
	lagrange, err := signerID.Lagrange(signerSet)
	if err != nil {
		return false
	}

	originalShare := pk.Shares[signerID]
	var weightedPublic ristretto.Element
	weightedPublic.ScalarMult(lagrange, originalShare)

	var publicNeg, rPrime ristretto.Element
	publicNeg.Negate(&weightedPublic)
	rPrime.VarTimeDoubleScalarBaseMult(challenge, &publicNeg, sigShare)

	return rPrime.Equal(nonceShare) == 1
}

func SignRound(secret *eddsa.SecretShare, pk *eddsa.Public, signerSet party.IDSlice, state *NonceState, preShares map[party.ID]*PreSignatureShare, message []byte) (*ristretto.Scalar, error) {
	bindingFactors := ComputeBindingFactors(signerSet, preShares, message)
	_, aggregateNonce := ComputeNonceCommitments(signerSet, preShares, bindingFactors)

	challenge := eddsa.ComputeChallenge(aggregateNonce, pk.GroupKey, message)

	lagrange, err := secret.ID.Lagrange(signerSet)
	if err != nil {
		return nil, err
	}

	rho := bindingFactors[secret.ID]

	var sigShare ristretto.Scalar
	sigShare.Multiply(lagrange, &secret.Secret)
	sigShare.Multiply(&sigShare, challenge)
	sigShare.MultiplyAdd(&state.E, rho, &sigShare)
	sigShare.Add(&sigShare, &state.D)

	return &sigShare, nil
}

func SignAgg(aggregateNonce *ristretto.Element, sigShares map[party.ID]*ristretto.Scalar) *eddsa.Signature {
	s := ristretto.NewScalar()
	for _, share := range sigShares {
		s.Add(s, share)
	}

	return &eddsa.Signature{
		R: *aggregateNonce,
		S: *s,
	}
}
