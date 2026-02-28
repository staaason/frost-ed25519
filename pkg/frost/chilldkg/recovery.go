package chilldkg

import (
	"encoding/binary"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func Recover(hostseckey *ristretto.Scalar, recoveryData *RecoveryData) (*DKGOutput, *SessionParams, error) {
	data := recoveryData.Data

	t, sumComs, hostpubkeys, pubnonces, encSecshares, cert, err := deserializeRecoveryData(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidRecoveryData, err)
	}

	n := len(hostpubkeys)
	params := &SessionParams{
		HostPubkeys: hostpubkeys,
		Threshold:   party.Size(t),
	}

	tBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tBytes, uint32(t))
	eqInput := append(tBytes, sumComs.toBytes()...)

	for _, ek := range hostpubkeys {
		eqInput = append(eqInput, ek.Bytes()...)
	}
	for _, pn := range pubnonces {
		eqInput = append(eqInput, pn.Bytes()...)
	}
	for _, share := range encSecshares {
		eqInput = append(eqInput, share.Bytes()...)
	}

	err = certeqVerify(hostpubkeys, eqInput, cert)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: certificate verification failed: %v", ErrInvalidRecoveryData, err)
	}

	thresholdPubkey := sumComs.commitmentToSecret()
	pubshares := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		pubshares[i].Set(sumComs.pubshare(i))
	}

	dkgOutput := &DKGOutput{
		ThresholdPubkey: *thresholdPubkey,
		PubShares:       pubshares,
	}

	if hostseckey != nil {
		hostpubkey := HostPubkeyGen(hostseckey)
		idx := -1
		for i, pk := range hostpubkeys {
			if pk.Equal(hostpubkey) == 1 {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, nil, ErrHostkeyMismatch
		}

		encContext := serializeEncContext(t, hostpubkeys)
		secshare := decryptSum(hostseckey, &hostpubkeys[idx], pubnonces, encContext, idx, encSecshares[idx])

		pubshare := sumComs.pubshare(idx)
		if !vssVerifySecshare(secshare, pubshare) {
			return nil, nil, fmt.Errorf("%w: recovered secshare does not match pubshare", ErrInvalidRecoveryData)
		}

		dkgOutput.SecShare = secshare
	}

	return dkgOutput, params, nil
}

func deserializeRecoveryData(data []byte) (int, *vssCommitment, []ristretto.Element, []ristretto.Element, []*ristretto.Scalar, []byte, error) {
	if len(data) < 4 {
		return 0, nil, nil, nil, nil, nil, fmt.Errorf("data too short for threshold")
	}
	t := int(binary.BigEndian.Uint32(data[:4]))
	rest := data[4:]

	if len(rest) < 32*t {
		return 0, nil, nil, nil, nil, nil, fmt.Errorf("data too short for VSS commitment")
	}
	points := make([]ristretto.Element, t)
	for i := 0; i < t; i++ {
		if _, err := points[i].SetCanonicalBytes(rest[i*32 : (i+1)*32]); err != nil {
			return 0, nil, nil, nil, nil, nil, fmt.Errorf("invalid VSS commitment point %d: %w", i, err)
		}
	}
	sumComs := &vssCommitment{points: points}
	rest = rest[32*t:]

	perParticipant := 32 + 32 + 32 + certeqSigSize
	if len(rest)%perParticipant != 0 {
		return 0, nil, nil, nil, nil, nil, fmt.Errorf("invalid recovery data length")
	}
	n := len(rest) / perParticipant

	hostpubkeys := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		if _, err := hostpubkeys[i].SetCanonicalBytes(rest[i*32 : (i+1)*32]); err != nil {
			return 0, nil, nil, nil, nil, nil, fmt.Errorf("invalid hostpubkey %d: %w", i, err)
		}
	}
	rest = rest[32*n:]

	pubnonces := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		if _, err := pubnonces[i].SetCanonicalBytes(rest[i*32 : (i+1)*32]); err != nil {
			return 0, nil, nil, nil, nil, nil, fmt.Errorf("invalid pubnonce %d: %w", i, err)
		}
	}
	rest = rest[32*n:]

	encSecshares := make([]*ristretto.Scalar, n)
	for i := 0; i < n; i++ {
		encSecshares[i] = new(ristretto.Scalar)
		if _, err := encSecshares[i].SetCanonicalBytes(rest[i*32 : (i+1)*32]); err != nil {
			return 0, nil, nil, nil, nil, nil, fmt.Errorf("invalid enc_secshare %d: %w", i, err)
		}
	}
	rest = rest[32*n:]

	cert := rest[:certeqSigSize*n]
	return t, sumComs, hostpubkeys, pubnonces, encSecshares, cert, nil
}
