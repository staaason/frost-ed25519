package experiments

import (
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/chilldkg"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestProof3_CertEqIntegrity_AllParticipantsAgree(t *testing.T) {
	configs := []struct {
		n, threshold int
	}{
		{3, 2}, {5, 3}, {7, 4},
	}

	for _, cfg := range configs {
		n := cfg.n
		threshold := cfg.threshold

		seckeys, pubkeys := generateHostKeys(n)
		params := &chilldkg.SessionParams{
			HostPubkeys: pubkeys,
			Threshold:   party.Size(threshold),
		}

		outputs, _, err := chilldkg.SimulateSession(seckeys, params)
		if err != nil {
			t.Fatalf("n=%d,t=%d: SimulateSession failed: %v", n, threshold, err)
		}

		refPubkey := outputs[0].ThresholdPubkey
		for i := 1; i < n; i++ {
			if outputs[i].ThresholdPubkey.Equal(&refPubkey) != 1 {
				t.Fatalf("n=%d,t=%d: participant %d has different threshold pubkey", n, threshold, i)
			}
		}

		for i := 0; i < n; i++ {
			for j := 0; j < n; j++ {
				if outputs[i].PubShares[j].Equal(&outputs[0].PubShares[j]) != 1 {
					t.Fatalf("n=%d,t=%d: participant %d sees different pubshare[%d]", n, threshold, i, j)
				}
			}
		}

		t.Logf("PASS n=%d, t=%d: all participants agree on threshold pubkey and all %d pubshares", n, threshold, n)
	}
}

func TestProof3_CertEqConditionalAgreement_RecoveryWithCert(t *testing.T) {
	n := 5
	threshold := 3

	seckeys, pubkeys := generateHostKeys(n)
	params := &chilldkg.SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   party.Size(threshold),
	}

	outputs, recoveryData, err := chilldkg.SimulateSession(seckeys, params)
	if err != nil {
		t.Fatalf("SimulateSession failed: %v", err)
	}

	for i := 0; i < n; i++ {
		recovered, recoveredParams, err := chilldkg.Recover(seckeys[i], recoveryData)
		if err != nil {
			t.Fatalf("participant %d: recovery failed: %v", i, err)
		}

		if recovered.ThresholdPubkey.Equal(&outputs[i].ThresholdPubkey) != 1 {
			t.Fatalf("participant %d: recovered threshold pubkey mismatch", i)
		}

		if int(recoveredParams.Threshold) != threshold {
			t.Fatalf("participant %d: recovered threshold %d != %d", i, recoveredParams.Threshold, threshold)
		}
	}

	t.Logf("PASS: all %d participants can recover using certificate (conditional agreement)", n)
}

func TestProof3_ShareConsistencyWithPubShares(t *testing.T) {
	n := 5
	threshold := 3

	seckeys, pubkeys := generateHostKeys(n)
	params := &chilldkg.SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   party.Size(threshold),
	}

	outputs, _, err := chilldkg.SimulateSession(seckeys, params)
	if err != nil {
		t.Fatalf("SimulateSession failed: %v", err)
	}

	for i := 0; i < n; i++ {
		var computedPub ristretto.Element
		computedPub.ScalarBaseMult(outputs[i].SecShare)
		if computedPub.Equal(&outputs[i].PubShares[i]) != 1 {
			t.Fatalf("participant %d: [s_i]G != PubShares[i]", i)
		}
	}
	t.Logf("PASS: all %d participants' secret shares are consistent with their public shares", n)
}

func TestProof3_ThresholdReconstructionFromChillDKG(t *testing.T) {
	n := 5
	threshold := 3

	seckeys, pubkeys := generateHostKeys(n)
	params := &chilldkg.SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   party.Size(threshold),
	}

	outputs, _, err := chilldkg.SimulateSession(seckeys, params)
	if err != nil {
		t.Fatalf("SimulateSession failed: %v", err)
	}

	subset := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		subset[i] = i + 1
	}

	shares := make([]*ristretto.Scalar, threshold)
	for idx, pt := range subset {
		shares[idx] = outputs[pt-1].SecShare
	}

	var reconstructed ristretto.Scalar
	reconstructed.Set(ristretto.NewScalar())
	for idx, pt := range subset {
		lambda := lagrangeCoeff(pt, subset)
		var term ristretto.Scalar
		term.Multiply(lambda, shares[idx])
		reconstructed.Add(&reconstructed, &term)
	}

	var reconstructedPub ristretto.Element
	reconstructedPub.ScalarBaseMult(&reconstructed)
	if reconstructedPub.Equal(&outputs[0].ThresholdPubkey) != 1 {
		t.Fatal("Lagrange reconstruction of secret from ChillDKG shares does not yield threshold pubkey")
	}
	t.Logf("PASS: reconstructed group secret from %d-of-%d ChillDKG shares matches threshold pubkey", threshold, n)

	subset2 := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		subset2[i] = n - threshold + i + 1
	}
	shares2 := make([]*ristretto.Scalar, threshold)
	for idx, pt := range subset2 {
		shares2[idx] = outputs[pt-1].SecShare
	}

	var reconstructed2 ristretto.Scalar
	reconstructed2.Set(ristretto.NewScalar())
	for idx, pt := range subset2 {
		lambda := lagrangeCoeff(pt, subset2)
		var term ristretto.Scalar
		term.Multiply(lambda, shares2[idx])
		reconstructed2.Add(&reconstructed2, &term)
	}

	if reconstructed2.Equal(&reconstructed) != 1 {
		t.Fatal("different subsets reconstruct different secrets")
	}
	t.Logf("PASS: two different %d-subsets of %d reconstruct the same group secret", threshold, n)
}

func TestProof3_TamperedCertificateRejected(t *testing.T) {
	n := 3
	threshold := 2

	seckeys, pubkeys := generateHostKeys(n)
	params := &chilldkg.SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   party.Size(threshold),
	}

	_, recoveryData, err := chilldkg.SimulateSession(seckeys, params)
	if err != nil {
		t.Fatalf("SimulateSession failed: %v", err)
	}

	tampered := make([]byte, len(recoveryData.Data))
	copy(tampered, recoveryData.Data)
	lastByte := len(tampered) - 1
	tampered[lastByte] ^= 0x01

	_, _, err = chilldkg.Recover(seckeys[0], &chilldkg.RecoveryData{Data: tampered})
	if err == nil {
		t.Fatal("recovery with tampered certificate should fail")
	}
	t.Logf("PASS: tampered certificate correctly rejected: %v", err)
}
