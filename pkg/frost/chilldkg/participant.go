package chilldkg

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type ParticipantState1 struct {
	params   *SessionParams
	idx      int
	encState *encPedPopParticipantState
}

type ParticipantState2 struct {
	params    *SessionParams
	eqInput   []byte
	dkgOutput *DKGOutput
}

type ParticipantMsg1 struct {
	encPmsg *encPedPopParticipantMsg
}

type ParticipantMsg2 struct {
	Sig []byte
}

func ParticipantStep1(
	hostseckey *ristretto.Scalar,
	params *SessionParams,
	random []byte,
) (*ParticipantState1, *ParticipantMsg1, error) {
	hostpubkey := HostPubkeyGen(hostseckey)

	if err := ParamsValidate(params); err != nil {
		return nil, nil, err
	}

	idx := -1
	for i, pk := range params.HostPubkeys {
		if pk.Equal(hostpubkey) == 1 {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, nil, ErrHostkeyMismatch
	}

	if len(random) != 32 {
		return nil, nil, ErrInvalidRandomness
	}

	encState, encPmsg, err := encPedPopParticipantStep1(
		hostseckey.Bytes(),
		hostseckey,
		params.HostPubkeys,
		int(params.Threshold),
		idx,
		random,
	)
	if err != nil {
		return nil, nil, err
	}

	state1 := &ParticipantState1{
		params:   params,
		idx:      idx,
		encState: encState,
	}
	pmsg1 := &ParticipantMsg1{
		encPmsg: encPmsg,
	}

	return state1, pmsg1, nil
}

func ParticipantStep2(
	hostseckey *ristretto.Scalar,
	state1 *ParticipantState1,
	cmsg1 *CoordinatorMsg1,
) (*ParticipantState2, *ParticipantMsg2, error) {
	hostpubkey := HostPubkeyGen(hostseckey)
	idx := state1.idx

	dkgOutput, eqInput, err := encPedPopParticipantStep2(
		state1.encState,
		hostseckey,
		cmsg1.encCmsg,
		cmsg1.encSecshares[idx],
	)
	if err != nil {
		return nil, nil, err
	}

	for _, share := range cmsg1.encSecshares {
		eqInput = append(eqInput, share.Bytes()...)
	}

	sig := certeqSign(hostseckey, hostpubkey, idx, eqInput)

	state2 := &ParticipantState2{
		params:    state1.params,
		eqInput:   eqInput,
		dkgOutput: dkgOutput,
	}
	pmsg2 := &ParticipantMsg2{
		Sig: sig,
	}

	return state2, pmsg2, nil
}

func ParticipantFinalize(
	state2 *ParticipantState2,
	cmsg2 *CoordinatorMsg2,
) (*DKGOutput, *RecoveryData, error) {
	err := certeqVerify(state2.params.HostPubkeys, state2.eqInput, cmsg2.Cert)
	if err != nil {
		return nil, nil, fmt.Errorf("chilldkg: finalize failed: %w", err)
	}

	recoveryBytes := append([]byte{}, state2.eqInput...)
	recoveryBytes = append(recoveryBytes, cmsg2.Cert...)

	return state2.dkgOutput, &RecoveryData{Data: recoveryBytes}, nil
}
