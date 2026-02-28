package chilldkg

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type CoordinatorMsg1 struct {
	encCmsg      *encPedPopCoordinatorMsg
	encSecshares []*ristretto.Scalar
}

type CoordinatorMsg2 struct {
	Cert []byte
}

type CoordinatorState struct {
	params    *SessionParams
	eqInput   []byte
	dkgOutput *DKGOutput
}

func CoordinatorStep1(
	pmsgs1 []*ParticipantMsg1,
	params *SessionParams,
) (*CoordinatorState, *CoordinatorMsg1, error) {
	if err := ParamsValidate(params); err != nil {
		return nil, nil, err
	}
	n := len(params.HostPubkeys)
	if len(pmsgs1) != n {
		return nil, nil, fmt.Errorf("chilldkg: expected %d participant messages, got %d", n, len(pmsgs1))
	}

	encPmsgs := make([]*encPedPopParticipantMsg, n)
	for i := 0; i < n; i++ {
		encPmsgs[i] = pmsgs1[i].encPmsg
	}

	encCmsg, dkgOutput, eqInput, encSecshares, err := encPedPopCoordinatorStep(
		encPmsgs,
		int(params.Threshold),
		params.HostPubkeys,
	)
	if err != nil {
		return nil, nil, err
	}

	for _, share := range encSecshares {
		eqInput = append(eqInput, share.Bytes()...)
	}

	state := &CoordinatorState{
		params:    params,
		eqInput:   eqInput,
		dkgOutput: dkgOutput,
	}

	cmsg1 := &CoordinatorMsg1{
		encCmsg:      encCmsg,
		encSecshares: encSecshares,
	}

	return state, cmsg1, nil
}

func CoordinatorFinalize(
	state *CoordinatorState,
	pmsgs2 []*ParticipantMsg2,
) (*CoordinatorMsg2, *DKGOutput, *RecoveryData, error) {
	n := len(state.params.HostPubkeys)
	if len(pmsgs2) != n {
		return nil, nil, nil, fmt.Errorf("chilldkg: expected %d signatures, got %d", n, len(pmsgs2))
	}

	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		if len(pmsgs2[i].Sig) != certeqSigSize {
			return nil, nil, nil, &FaultyParticipantError{
				Index: i,
				Msg:   fmt.Sprintf("chilldkg: participant %d sent invalid signature length", i),
			}
		}
		sigs[i] = pmsgs2[i].Sig
	}

	var cert []byte
	for _, sig := range sigs {
		cert = append(cert, sig...)
	}

	err := certeqVerify(state.params.HostPubkeys, state.eqInput, cert)
	if err != nil {
		return nil, nil, nil, err
	}

	recoveryBytes := append([]byte{}, state.eqInput...)
	recoveryBytes = append(recoveryBytes, cert...)

	cmsg2 := &CoordinatorMsg2{
		Cert: cert,
	}

	return cmsg2, state.dkgOutput, &RecoveryData{Data: recoveryBytes}, nil
}
