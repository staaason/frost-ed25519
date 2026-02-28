package chilldkg

import (
	"crypto/rand"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func GenerateHostKey() (*ristretto.Scalar, *ristretto.Element, error) {
	randomBytes := make([]byte, 64)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, nil, err
	}
	var seckey ristretto.Scalar
	if _, err := seckey.SetUniformBytes(randomBytes); err != nil {
		return nil, nil, err
	}
	pubkey := HostPubkeyGen(&seckey)
	return &seckey, pubkey, nil
}

func SimulateSession(hostseckeys []*ristretto.Scalar, params *SessionParams) ([]*DKGOutput, *RecoveryData, error) {
	n := len(hostseckeys)

	pmsgs1 := make([]*ParticipantMsg1, n)
	pstates1 := make([]*ParticipantState1, n)

	for i := 0; i < n; i++ {
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return nil, nil, err
		}
		state1, pmsg1, err := ParticipantStep1(hostseckeys[i], params, random)
		if err != nil {
			return nil, nil, err
		}
		pstates1[i] = state1
		pmsgs1[i] = pmsg1
	}

	coordState, cmsg1, err := CoordinatorStep1(pmsgs1, params)
	if err != nil {
		return nil, nil, err
	}

	pmsgs2 := make([]*ParticipantMsg2, n)
	pstates2 := make([]*ParticipantState2, n)

	for i := 0; i < n; i++ {
		state2, pmsg2, err := ParticipantStep2(hostseckeys[i], pstates1[i], cmsg1)
		if err != nil {
			return nil, nil, err
		}
		pstates2[i] = state2
		pmsgs2[i] = pmsg2
	}

	cmsg2, _, recoveryData, err := CoordinatorFinalize(coordState, pmsgs2)
	if err != nil {
		return nil, nil, err
	}

	outputs := make([]*DKGOutput, n)
	for i := 0; i < n; i++ {
		output, _, err := ParticipantFinalize(pstates2[i], cmsg2)
		if err != nil {
			return nil, nil, err
		}
		outputs[i] = output
	}

	return outputs, recoveryData, nil
}

func OutputToFROST(outputs []*DKGOutput, params *SessionParams) (*eddsa.Public, []*eddsa.SecretShare, error) {
	n := len(outputs)
	partyIDs := make([]party.ID, n)
	for i := 0; i < n; i++ {
		partyIDs[i] = party.ID(i + 1)
	}
	shares := make(map[party.ID]*ristretto.Element, n)
	for i := 0; i < n; i++ {
		shares[partyIDs[i]] = &outputs[0].PubShares[i]
	}

	pub, err := eddsa.NewPublic(shares, params.Threshold)
	if err != nil {
		return nil, nil, err
	}

	secretShares := make([]*eddsa.SecretShare, n)
	for i := 0; i < n; i++ {
		secretShares[i] = eddsa.NewSecretShare(partyIDs[i], outputs[i].SecShare)
	}

	return pub, secretShares, nil
}
