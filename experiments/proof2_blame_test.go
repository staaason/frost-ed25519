package experiments

import (
	"crypto/rand"
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/chilldkg"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func generateHostKeys(n int) ([]*ristretto.Scalar, []ristretto.Element) {
	seckeys := make([]*ristretto.Scalar, n)
	pubkeys := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		sk, pk, _ := chilldkg.GenerateHostKey()
		seckeys[i] = sk
		pubkeys[i] = *pk
	}
	return seckeys, pubkeys
}

func TestProof2_FeldmanVSSVerification(t *testing.T) {
	configs := []struct {
		n, threshold int
	}{
		{3, 2}, {5, 3}, {7, 4},
	}

	for _, cfg := range configs {
		n := cfg.n
		threshold := cfg.threshold

		polys := make([]*poly, n)
		commits := make([][]*ristretto.Element, n)
		allShares := make([][]*ristretto.Scalar, n)

		for j := 0; j < n; j++ {
			polys[j] = newRandomPoly(threshold - 1)
			commits[j] = polys[j].commitment()
			shares := make([]*ristretto.Scalar, n)
			for i := 0; i < n; i++ {
				x := scalarFromUint32(uint32(i + 1))
				shares[i] = polys[j].eval(x)
			}
			allShares[j] = shares
		}

		for i := 0; i < n; i++ {
			for j := 0; j < n; j++ {
				s_ji := allShares[j][i]

				var lhs ristretto.Element
				lhs.ScalarBaseMult(s_ji)

				var rhs ristretto.Element
				rhs.Set(ristretto.NewIdentityElement())
				xVal := uint32(i + 1)
				xPow := scalarFromUint32(1)
				for k := 0; k < threshold; k++ {
					var term ristretto.Element
					term.ScalarMult(xPow, commits[j][k])
					rhs.Add(&rhs, &term)
					xPow.Multiply(xPow, scalarFromUint32(xVal))
				}

				if lhs.Equal(&rhs) != 1 {
					t.Fatalf("n=%d,t=%d: Feldman verification failed for share from P_%d to P_%d", n, threshold, j, i)
				}
			}
		}
		t.Logf("PASS n=%d, t=%d: all %d*%d Feldman VSS verifications passed", n, threshold, n, n)
	}
}

func TestProof2_BlameSoundness_HonestNeverBlamed(t *testing.T) {
	n := 5
	threshold := 3

	polys := make([]*poly, n)
	commits := make([][]*ristretto.Element, n)
	allShares := make([][]*ristretto.Scalar, n)

	for j := 0; j < n; j++ {
		polys[j] = newRandomPoly(threshold - 1)
		commits[j] = polys[j].commitment()
		shares := make([]*ristretto.Scalar, n)
		for i := 0; i < n; i++ {
			x := scalarFromUint32(uint32(i + 1))
			shares[i] = polys[j].eval(x)
		}
		allShares[j] = shares
	}

	for i := 0; i < n; i++ {
		blamedCount := 0
		for j := 0; j < n; j++ {
			s_ji := allShares[j][i]

			var lhs ristretto.Element
			lhs.ScalarBaseMult(s_ji)

			var rhs ristretto.Element
			rhs.Set(ristretto.NewIdentityElement())
			xVal := uint32(i + 1)
			xPow := scalarFromUint32(1)
			for k := 0; k < threshold; k++ {
				var term ristretto.Element
				term.ScalarMult(xPow, commits[j][k])
				rhs.Add(&rhs, &term)
				xPow.Multiply(xPow, scalarFromUint32(xVal))
			}

			if lhs.Equal(&rhs) != 1 {
				blamedCount++
			}
		}
		if blamedCount > 0 {
			t.Fatalf("honest participant P_%d was blamed %d times", i, blamedCount)
		}
	}
	t.Logf("PASS: no honest participant blamed in %d-of-%d setup", threshold, n)
}

func TestProof2_BlameCompleteness_TamperedShareDetected(t *testing.T) {
	n := 5
	threshold := 3
	faultyIdx := 2
	targetIdx := 0

	polys := make([]*poly, n)
	commits := make([][]*ristretto.Element, n)
	allShares := make([][]*ristretto.Scalar, n)

	for j := 0; j < n; j++ {
		polys[j] = newRandomPoly(threshold - 1)
		commits[j] = polys[j].commitment()
		shares := make([]*ristretto.Scalar, n)
		for i := 0; i < n; i++ {
			x := scalarFromUint32(uint32(i + 1))
			shares[i] = polys[j].eval(x)
		}
		allShares[j] = shares
	}

	tamperedShare := randomScalar()
	allShares[faultyIdx][targetIdx] = tamperedShare

	var aggShare ristretto.Scalar
	aggShare.Set(ristretto.NewScalar())
	for j := 0; j < n; j++ {
		aggShare.Add(&aggShare, allShares[j][targetIdx])
	}

	var aggPubShare ristretto.Element
	aggPubShare.Set(ristretto.NewIdentityElement())
	for j := 0; j < n; j++ {
		xVal := uint32(targetIdx + 1)
		xPow := scalarFromUint32(1)
		for k := 0; k < threshold; k++ {
			var term ristretto.Element
			term.ScalarMult(xPow, commits[j][k])
			aggPubShare.Add(&aggPubShare, &term)
			xPow.Multiply(xPow, scalarFromUint32(xVal))
		}
	}

	var aggLhs ristretto.Element
	aggLhs.ScalarBaseMult(&aggShare)
	if aggLhs.Equal(&aggPubShare) == 1 {
		t.Fatal("tampered share should cause aggregated verification to fail")
	}
	t.Log("Step 1: aggregated share verification correctly fails")

	blamedIdx := -1
	for j := 0; j < n; j++ {
		s_ji := allShares[j][targetIdx]
		var lhs ristretto.Element
		lhs.ScalarBaseMult(s_ji)

		var rhs ristretto.Element
		rhs.Set(ristretto.NewIdentityElement())
		xVal := uint32(targetIdx + 1)
		xPow := scalarFromUint32(1)
		for k := 0; k < threshold; k++ {
			var term ristretto.Element
			term.ScalarMult(xPow, commits[j][k])
			rhs.Add(&rhs, &term)
			xPow.Multiply(xPow, scalarFromUint32(xVal))
		}

		if lhs.Equal(&rhs) != 1 {
			blamedIdx = j
			break
		}
	}

	if blamedIdx == -1 {
		t.Fatal("investigation should identify at least one faulty participant")
	}
	if blamedIdx != faultyIdx {
		t.Fatalf("blamed P_%d but faulty is P_%d", blamedIdx, faultyIdx)
	}
	t.Logf("PASS: investigation correctly identified P_%d as faulty", blamedIdx)
}

func TestProof2_PublicVerifiability(t *testing.T) {
	n := 5
	threshold := 3
	faultyIdx := 1
	targetIdx := 3

	polys := make([]*poly, n)
	commits := make([][]*ristretto.Element, n)
	allShares := make([][]*ristretto.Scalar, n)

	for j := 0; j < n; j++ {
		polys[j] = newRandomPoly(threshold - 1)
		commits[j] = polys[j].commitment()
		shares := make([]*ristretto.Scalar, n)
		for i := 0; i < n; i++ {
			x := scalarFromUint32(uint32(i + 1))
			shares[i] = polys[j].eval(x)
		}
		allShares[j] = shares
	}

	badShare := randomScalar()
	allShares[faultyIdx][targetIdx] = badShare

	blameEvidence := struct {
		i, j   int
		s_ji   *ristretto.Scalar
		commit []*ristretto.Element
	}{
		i:      targetIdx,
		j:      faultyIdx,
		s_ji:   allShares[faultyIdx][targetIdx],
		commit: commits[faultyIdx],
	}

	var lhs ristretto.Element
	lhs.ScalarBaseMult(blameEvidence.s_ji)

	var rhs ristretto.Element
	rhs.Set(ristretto.NewIdentityElement())
	xVal := uint32(blameEvidence.i + 1)
	xPow := scalarFromUint32(1)
	for k := 0; k < threshold; k++ {
		var term ristretto.Element
		term.ScalarMult(xPow, blameEvidence.commit[k])
		rhs.Add(&rhs, &term)
		xPow.Multiply(xPow, scalarFromUint32(xVal))
	}

	if lhs.Equal(&rhs) == 1 {
		t.Fatal("public verifier should detect the invalid share")
	}
	t.Logf("PASS: third party verified blame proof (P_%d sent invalid share to P_%d) using only public data", blameEvidence.j, blameEvidence.i)
}

func TestProof2_BlameWithRealChillDKG(t *testing.T) {
	n := 3
	threshold := 2

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
		var expectedPub ristretto.Element
		expectedPub.ScalarBaseMult(outputs[i].SecShare)
		if expectedPub.Equal(&outputs[i].PubShares[i]) != 1 {
			t.Fatalf("participant %d: [s_i]G != pubshare[i]", i)
		}
	}
	t.Logf("PASS: real ChillDKG session — all %d participants' shares match their public shares", n)
}

func TestProof2_RecoveryIntegrity(t *testing.T) {
	n := 3
	threshold := 2

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
		recovered, _, err := chilldkg.Recover(seckeys[i], recoveryData)
		if err != nil {
			t.Fatalf("Recovery failed for participant %d: %v", i, err)
		}
		if recovered.SecShare.Equal(outputs[i].SecShare) != 1 {
			t.Fatalf("participant %d: recovered share != original share", i)
		}
	}
	t.Logf("PASS: recovery produces identical shares for all %d participants", n)

	tampered := make([]byte, len(recoveryData.Data))
	copy(tampered, recoveryData.Data)
	if len(tampered) > 10 {
		tampered[10] ^= 0xFF
	}
	_, _, err = chilldkg.Recover(seckeys[0], &chilldkg.RecoveryData{Data: tampered})
	if err == nil {
		t.Fatal("recovery with tampered data should fail")
	}
	t.Logf("PASS: recovery correctly rejects tampered data: %v", err)
}

func init() {
	_ = rand.Reader
}
