package chilldkg

import (
	"encoding/binary"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type simplPedPopParticipantState struct {
	t           int
	n           int
	idx         int
	comToSecret ristretto.Element
}

type simplPedPopParticipantMsg struct {
	com vssCommitment
	pop []byte
}

type simplPedPopCoordinatorMsg struct {
	comsToSecrets          []ristretto.Element
	sumComsToNonconstTerms []ristretto.Element
	pops                   [][]byte
}

func simplPedPopParticipantStep1(seed []byte, t, n, idx int, auxRand []byte) (
	*simplPedPopParticipantState,
	*simplPedPopParticipantMsg,
	[]*ristretto.Scalar,
	error,
) {
	if t > n {
		return nil, nil, nil, ErrThresholdOrCount
	}
	if idx >= n {
		return nil, nil, nil, fmt.Errorf("chilldkg: index %d out of range for n=%d", idx, n)
	}
	if len(seed) != 32 {
		return nil, nil, nil, ErrInvalidRandomness
	}
	if len(auxRand) != 32 {
		return nil, nil, nil, ErrInvalidRandomness
	}

	vss := vssGenerate(seed, t)
	partialSecshares := vss.secshares(n)

	secretKey := vss.secret()
	var pubKey ristretto.Element
	pubKey.ScalarBaseMult(secretKey)

	idxBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBytes, uint32(idx))
	popMsg := idxBytes
	pop := schnorrSign(secretKey, &pubKey, popMsg)

	com := vss.commit()
	comToSecret := com.commitmentToSecret()

	state := &simplPedPopParticipantState{
		t:           t,
		n:           n,
		idx:         idx,
		comToSecret: *comToSecret,
	}

	pmsg := &simplPedPopParticipantMsg{
		com: *com,
		pop: pop,
	}

	return state, pmsg, partialSecshares, nil
}

func simplPedPopCoordinatorStep(pmsgs []*simplPedPopParticipantMsg, t, n int) (
	*simplPedPopCoordinatorMsg,
	*DKGOutput,
	[]byte,
	error,
) {
	if len(pmsgs) != n {
		return nil, nil, nil, fmt.Errorf("chilldkg: expected %d messages, got %d", n, len(pmsgs))
	}

	comsToSecrets := make([]ristretto.Element, n)
	pops := make([][]byte, n)

	sumComsToNonconstTerms := make([]ristretto.Element, t-1)
	for i := 0; i < t-1; i++ {
		sumComsToNonconstTerms[i].Set(ristretto.NewIdentityElement())
	}

	for i := 0; i < n; i++ {
		comsToSecrets[i].Set(pmsgs[i].com.commitmentToSecret())
		pops[i] = pmsgs[i].pop

		nonconstTerms := pmsgs[i].com.commitmentToNonconstTerms()
		for j := 0; j < len(nonconstTerms); j++ {
			sumComsToNonconstTerms[j].Add(&sumComsToNonconstTerms[j], &nonconstTerms[j])
		}
	}

	var thresholdPubkey ristretto.Element
	thresholdPubkey.Set(ristretto.NewIdentityElement())
	for i := 0; i < n; i++ {
		thresholdPubkey.Add(&thresholdPubkey, &comsToSecrets[i])
	}

	sumComs := assembleSumComs(comsToSecrets, sumComsToNonconstTerms)

	pubshares := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		pubshares[i].Set(sumComs.pubshare(i))
	}

	tBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tBytes, uint32(t))
	eqInput := append(tBytes, sumComs.toBytes()...)

	cmsg := &simplPedPopCoordinatorMsg{
		comsToSecrets:          comsToSecrets,
		sumComsToNonconstTerms: sumComsToNonconstTerms,
		pops:                   pops,
	}

	dkgOutput := &DKGOutput{
		SecShare:        nil,
		ThresholdPubkey: thresholdPubkey,
		PubShares:       pubshares,
	}

	return cmsg, dkgOutput, eqInput, nil
}

func simplPedPopParticipantStep2(
	state *simplPedPopParticipantState,
	cmsg *simplPedPopCoordinatorMsg,
	secshare *ristretto.Scalar,
) (*DKGOutput, []byte, error) {
	t := state.t
	n := state.n
	idx := state.idx

	if cmsg.comsToSecrets[idx].Equal(&state.comToSecret) != 1 {
		return nil, nil, fmt.Errorf("%w: coordinator sent wrong commitment for local index", ErrFaultyCoordinator)
	}

	for i := 0; i < n; i++ {
		if i == idx {
			continue
		}
		pk := &cmsg.comsToSecrets[i]
		if pk.Equal(ristretto.NewIdentityElement()) == 1 {
			return nil, nil, &FaultyParticipantError{
				Index: i,
				Msg:   fmt.Sprintf("chilldkg: participant %d sent identity as commitment", i),
			}
		}

		idxBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idxBytes, uint32(i))
		if !schnorrVerify(pk, idxBytes, cmsg.pops[i]) {
			return nil, nil, &FaultyParticipantError{
				Index: i,
				Msg:   fmt.Sprintf("chilldkg: participant %d sent invalid proof of possession", i),
			}
		}
	}

	sumComs := assembleSumComs(cmsg.comsToSecrets, cmsg.sumComsToNonconstTerms)

	pubshare := sumComs.pubshare(idx)
	if !vssVerifySecshare(secshare, pubshare) {
		return nil, nil, fmt.Errorf("%w: received invalid secshare", ErrFaultyParticipantOrCoord)
	}

	thresholdPubkey := sumComs.commitmentToSecret()

	pubshares := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		if i == idx {
			pubshares[i].Set(pubshare)
		} else {
			pubshares[i].Set(sumComs.pubshare(i))
		}
	}

	secshareBytes := secshare.Bytes()
	secshareScalar := new(ristretto.Scalar)
	_, _ = secshareScalar.SetCanonicalBytes(secshareBytes)

	dkgOutput := &DKGOutput{
		SecShare:        secshareScalar,
		ThresholdPubkey: *thresholdPubkey,
		PubShares:       pubshares,
	}

	tBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tBytes, uint32(t))
	eqInput := append(tBytes, sumComs.toBytes()...)

	return dkgOutput, eqInput, nil
}

func assembleSumComs(comsToSecrets []ristretto.Element, sumComsToNonconstTerms []ristretto.Element) *vssCommitment {
	var sumSecret ristretto.Element
	sumSecret.Set(ristretto.NewIdentityElement())
	for i := range comsToSecrets {
		sumSecret.Add(&sumSecret, &comsToSecrets[i])
	}
	return vssCommitmentFromParts(&sumSecret, sumComsToNonconstTerms)
}
