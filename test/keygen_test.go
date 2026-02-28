package main

import (
	"errors"
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/chilldkg"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestKeygen(t *testing.T) {
	N := party.Size(50)
	T := N / 2

	n := int(N)
	seckeys := make([]*ristretto.Scalar, n)
	pubkeys := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		sk, pk, err := chilldkg.GenerateHostKey()
		if err != nil {
			t.Fatal(err)
		}
		seckeys[i] = sk
		pubkeys[i] = *pk
	}

	params := &chilldkg.SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   T,
	}

	outputs, _, err := chilldkg.SimulateSession(seckeys, params)
	if err != nil {
		t.Fatal(err)
	}

	public, secretSharesList, err := chilldkg.OutputToFROST(outputs, params)
	if err != nil {
		t.Fatal(err)
	}

	groupKey1 := public.GroupKey
	secrets := map[party.ID]*eddsa.SecretShare{}
	for i, ss := range secretSharesList {
		id := party.ID(i + 1)
		secrets[id] = ss
	}

	if err := ValidateSecrets(secrets, groupKey1, public); err != nil {
		t.Error(err)
	}
}

func CompareOutput(groupKey1, groupKey2 *eddsa.PublicKey, publicShares1, publicShares2 *eddsa.Public) error {
	if !publicShares1.Equal(publicShares2) {
		return errors.New("shares not equal")
	}
	partyIDs1 := publicShares1.PartyIDs
	partyIDs2 := publicShares2.PartyIDs
	if len(partyIDs1) != len(partyIDs2) {
		return errors.New("partyIDs are not the same length")
	}

	for i, id1 := range partyIDs1 {
		if id1 != partyIDs2[i] {
			return errors.New("partyIDs are not the same")
		}

		public1 := publicShares1.Shares[partyIDs1[i]]
		public2 := publicShares2.Shares[partyIDs2[i]]
		if public1.Equal(public2) != 1 {
			return errors.New("different public keys")
		}
	}

	groupKeyComp1 := publicShares1.GroupKey
	groupKeyComp2 := publicShares2.GroupKey

	if !groupKey1.Equal(groupKeyComp1) {
		return errors.New("groupKey1 is not computed the same way")
	}
	if !groupKey2.Equal(groupKeyComp2) {
		return errors.New("groupKey2 is not computed the same way")
	}
	return nil
}

func ValidateSecrets(secrets map[party.ID]*eddsa.SecretShare, groupKey *eddsa.PublicKey, shares *eddsa.Public) error {
	fullSecret := ristretto.NewScalar()

	for id, secret := range secrets {
		pk1 := &secret.Public
		pk2, ok := shares.Shares[id]
		if !ok {
			return errors.New("party %d has no share")
		}

		if pk1.Equal(pk2) != 1 {
			return errors.New("pk not the same")
		}

		lagrange, err := id.Lagrange(shares.PartyIDs)
		if err != nil {
			return err
		}
		fullSecret.MultiplyAdd(lagrange, &secret.Secret, fullSecret)
	}

	fullPk := eddsa.NewPublicKeyFromPoint(new(ristretto.Element).ScalarBaseMult(fullSecret))
	if !groupKey.Equal(fullPk) {
		return errors.New("computed groupKey does not match")
	}

	return nil
}
