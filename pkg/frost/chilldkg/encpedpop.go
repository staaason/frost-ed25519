package chilldkg

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type encPedPopParticipantState struct {
	simplState *simplPedPopParticipantState
	pubnonce   ristretto.Element
	enckeys    []ristretto.Element
	idx        int
}

type encPedPopParticipantMsg struct {
	simplPmsg *simplPedPopParticipantMsg
	pubnonce  ristretto.Element
	encShares []*ristretto.Scalar
}

type encPedPopCoordinatorMsg struct {
	simplCmsg *simplPedPopCoordinatorMsg
	pubnonces []ristretto.Element
}

func encPedPopParticipantStep1(
	seed []byte,
	deckey *ristretto.Scalar,
	enckeys []ristretto.Element,
	t int,
	idx int,
	random []byte,
) (*encPedPopParticipantState, *encPedPopParticipantMsg, error) {
	if len(random) != 32 {
		return nil, nil, ErrInvalidRandomness
	}
	n := len(enckeys)

	encContext := serializeEncContext(t, enckeys)
	simplSeed := taggedHash("encpedpop seed", seed, random, encContext)
	simplAuxRand := taggedHash("simplpedpop aux", simplSeed)
	secnonce := taggedHashScalar("encpedpop secnonce", simplSeed)

	var pubnonce ristretto.Element
	pubnonce.ScalarBaseMult(secnonce)

	simplState, simplPmsg, shares, err := simplPedPopParticipantStep1(simplSeed, t, n, idx, simplAuxRand)
	if err != nil {
		return nil, nil, err
	}

	encShares := encryptMulti(secnonce, &pubnonce, deckey, enckeys, encContext, idx, shares)

	state := &encPedPopParticipantState{
		simplState: simplState,
		pubnonce:   pubnonce,
		enckeys:    enckeys,
		idx:        idx,
	}

	pmsg := &encPedPopParticipantMsg{
		simplPmsg: simplPmsg,
		pubnonce:  pubnonce,
		encShares: encShares,
	}

	return state, pmsg, nil
}

func encPedPopCoordinatorStep(
	pmsgs []*encPedPopParticipantMsg,
	t int,
	enckeys []ristretto.Element,
) (*encPedPopCoordinatorMsg, *DKGOutput, []byte, []*ristretto.Scalar, error) {
	n := len(pmsgs)
	if n != len(enckeys) {
		return nil, nil, nil, nil, fmt.Errorf("chilldkg: message count %d != enckey count %d", n, len(enckeys))
	}

	simplPmsgs := make([]*simplPedPopParticipantMsg, n)
	pubnonces := make([]ristretto.Element, n)

	for i := 0; i < n; i++ {
		simplPmsgs[i] = pmsgs[i].simplPmsg
		pubnonces[i].Set(&pmsgs[i].pubnonce)
	}

	simplCmsg, dkgOutput, eqInput, err := simplPedPopCoordinatorStep(simplPmsgs, t, n)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	encSecshares := make([]*ristretto.Scalar, n)
	for i := 0; i < n; i++ {
		var sum ristretto.Scalar
		sum.Set(ristretto.NewScalar())
		for j := 0; j < n; j++ {
			sum.Add(&sum, pmsgs[j].encShares[i])
		}
		encSecshares[i] = new(ristretto.Scalar)
		encSecshares[i].Set(&sum)
	}

	for _, ek := range enckeys {
		eqInput = append(eqInput, ek.Bytes()...)
	}
	for _, pn := range pubnonces {
		eqInput = append(eqInput, pn.Bytes()...)
	}

	cmsg := &encPedPopCoordinatorMsg{
		simplCmsg: simplCmsg,
		pubnonces: pubnonces,
	}

	return cmsg, dkgOutput, eqInput, encSecshares, nil
}

func encPedPopParticipantStep2(
	state *encPedPopParticipantState,
	deckey *ristretto.Scalar,
	cmsg *encPedPopCoordinatorMsg,
	encSecshare *ristretto.Scalar,
) (*DKGOutput, []byte, error) {
	idx := state.idx

	reportedPubnonce := &cmsg.pubnonces[idx]
	if reportedPubnonce.Equal(&state.pubnonce) != 1 {
		return nil, nil, fmt.Errorf("%w: coordinator replied with wrong pubnonce", ErrFaultyCoordinator)
	}

	encContext := serializeEncContext(state.simplState.t, state.enckeys)
	pads := decapsMulti(deckey, &state.enckeys[idx], cmsg.pubnonces, encContext, idx)

	var sumPads ristretto.Scalar
	sumPads.Set(ristretto.NewScalar())
	for _, pad := range pads {
		sumPads.Add(&sumPads, pad)
	}

	var secshare ristretto.Scalar
	secshare.Subtract(encSecshare, &sumPads)

	dkgOutput, eqInput, err := simplPedPopParticipantStep2(state.simplState, cmsg.simplCmsg, &secshare)
	if err != nil {
		return nil, nil, err
	}

	for _, ek := range state.enckeys {
		eqInput = append(eqInput, ek.Bytes()...)
	}
	for _, pn := range cmsg.pubnonces {
		eqInput = append(eqInput, pn.Bytes()...)
	}

	return dkgOutput, eqInput, nil
}
