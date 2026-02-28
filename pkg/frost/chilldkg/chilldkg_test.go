package chilldkg

import (
	"crypto/rand"
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func generateHostKeys(n int) ([]*ristretto.Scalar, []ristretto.Element) {
	seckeys := make([]*ristretto.Scalar, n)
	pubkeys := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		sk, pk, _ := GenerateHostKey()
		seckeys[i] = sk
		pubkeys[i] = *pk
	}
	return seckeys, pubkeys
}

func TestSchnorrSignVerify(t *testing.T) {
	sk, pk, _ := GenerateHostKey()
	msg := []byte("test message for schnorr")
	sig := schnorrSign(sk, pk, msg)

	if !schnorrVerify(pk, msg, sig) {
		t.Fatal("schnorr verify failed for valid signature")
	}

	wrongMsg := []byte("wrong message")
	if schnorrVerify(pk, wrongMsg, sig) {
		t.Fatal("schnorr verify should fail for wrong message")
	}

	_, pk2, _ := GenerateHostKey()
	if schnorrVerify(pk2, msg, sig) {
		t.Fatal("schnorr verify should fail for wrong pubkey")
	}
}

func TestCertEq(t *testing.T) {
	n := 3
	seckeys, pubkeys := generateHostKeys(n)

	eqInput := []byte("test equality check input data")

	var cert []byte
	for i := 0; i < n; i++ {
		sig := certeqSign(seckeys[i], &pubkeys[i], i, eqInput)
		cert = append(cert, sig...)
	}

	err := certeqVerify(pubkeys, eqInput, cert)
	if err != nil {
		t.Fatalf("certeq verify failed: %v", err)
	}

	wrongInput := []byte("wrong input")
	err = certeqVerify(pubkeys, wrongInput, cert)
	if err == nil {
		t.Fatal("certeq verify should fail for wrong input")
	}
}

func TestVSSBasic(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)

	threshold := 2
	n := 3

	vss := vssGenerate(seed, threshold)
	shares := vss.secshares(n)
	com := vss.commit()

	for i := 0; i < n; i++ {
		pubshare := com.pubshare(i)
		if !vssVerifySecshare(shares[i], pubshare) {
			t.Fatalf("share %d failed verification", i)
		}
	}

	secret := vss.secret()
	comToSecret := com.commitmentToSecret()
	var expectedPub ristretto.Element
	expectedPub.ScalarBaseMult(secret)
	if expectedPub.Equal(comToSecret) != 1 {
		t.Fatal("commitment to secret does not match")
	}
}

func TestParamsValidation(t *testing.T) {
	_, pubkeys := generateHostKeys(3)

	params := &SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   2,
	}
	if err := ParamsValidate(params); err != nil {
		t.Fatalf("valid params should not error: %v", err)
	}

	badParams := &SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   0,
	}
	if err := ParamsValidate(badParams); err == nil {
		t.Fatal("threshold 0 should fail")
	}

	badParams2 := &SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   4,
	}
	if err := ParamsValidate(badParams2); err == nil {
		t.Fatal("threshold > n should fail")
	}

	dupPubkeys := []ristretto.Element{pubkeys[0], pubkeys[0], pubkeys[2]}
	dupParams := &SessionParams{
		HostPubkeys: dupPubkeys,
		Threshold:   2,
	}
	if err := ParamsValidate(dupParams); err == nil {
		t.Fatal("duplicate pubkeys should fail")
	}
}

func TestFullChillDKG_2of3(t *testing.T) {
	testFullSession(t, 2, 3)
}

func TestFullChillDKG_3of5(t *testing.T) {
	testFullSession(t, 3, 5)
}

func TestFullChillDKG_1of2(t *testing.T) {
	testFullSession(t, 1, 2)
}

func testFullSession(t *testing.T, threshold int, n int) {
	t.Helper()
	seckeys, pubkeys := generateHostKeys(n)

	params := &SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   party.Size(threshold),
	}

	outputs, recoveryData, err := SimulateSession(seckeys, params)
	if err != nil {
		t.Fatalf("SimulateSession failed: %v", err)
	}

	if len(outputs) != n {
		t.Fatalf("expected %d outputs, got %d", n, len(outputs))
	}

	for i := 0; i < n; i++ {
		if outputs[i].SecShare == nil {
			t.Fatalf("participant %d has nil secshare", i)
		}
	}

	for i := 1; i < n; i++ {
		if outputs[i].ThresholdPubkey.Equal(&outputs[0].ThresholdPubkey) != 1 {
			t.Fatalf("participant %d has different threshold pubkey", i)
		}
	}

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if outputs[i].PubShares[j].Equal(&outputs[0].PubShares[j]) != 1 {
				t.Fatalf("participant %d has different pubshare[%d]", i, j)
			}
		}
	}

	for i := 0; i < n; i++ {
		var expectedPub ristretto.Element
		expectedPub.ScalarBaseMult(outputs[i].SecShare)
		if expectedPub.Equal(&outputs[i].PubShares[i]) != 1 {
			t.Fatalf("participant %d secshare does not match pubshare", i)
		}
	}

	if recoveryData == nil || len(recoveryData.Data) == 0 {
		t.Fatal("recovery data is empty")
	}
}

func TestRecovery(t *testing.T) {
	n := 3
	threshold := 2
	seckeys, pubkeys := generateHostKeys(n)

	params := &SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   party.Size(threshold),
	}

	outputs, recoveryData, err := SimulateSession(seckeys, params)
	if err != nil {
		t.Fatalf("SimulateSession failed: %v", err)
	}

	for i := 0; i < n; i++ {
		recovered, recoveredParams, err := Recover(seckeys[i], recoveryData)
		if err != nil {
			t.Fatalf("Recover failed for participant %d: %v", i, err)
		}

		if recovered.SecShare == nil {
			t.Fatalf("recovered participant %d has nil secshare", i)
		}

		if recovered.SecShare.Equal(outputs[i].SecShare) != 1 {
			t.Fatalf("recovered participant %d secshare does not match", i)
		}

		if recovered.ThresholdPubkey.Equal(&outputs[i].ThresholdPubkey) != 1 {
			t.Fatalf("recovered participant %d threshold pubkey does not match", i)
		}

		if int(recoveredParams.Threshold) != threshold {
			t.Fatalf("recovered threshold %d != %d", recoveredParams.Threshold, threshold)
		}
	}

	recoveredCoord, _, err := Recover(nil, recoveryData)
	if err != nil {
		t.Fatalf("Recover failed for coordinator: %v", err)
	}
	if recoveredCoord.SecShare != nil {
		t.Fatal("coordinator recovery should have nil secshare")
	}
	if recoveredCoord.ThresholdPubkey.Equal(&outputs[0].ThresholdPubkey) != 1 {
		t.Fatal("coordinator recovered wrong threshold pubkey")
	}
}

func TestOutputToFROST(t *testing.T) {
	n := 3
	threshold := 2
	seckeys, pubkeys := generateHostKeys(n)

	params := &SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   party.Size(threshold),
	}

	outputs, _, err := SimulateSession(seckeys, params)
	if err != nil {
		t.Fatalf("SimulateSession failed: %v", err)
	}

	pub, secretShares, err := OutputToFROST(outputs, params)
	if err != nil {
		t.Fatalf("OutputToFROST failed: %v", err)
	}

	if pub == nil {
		t.Fatal("pub is nil")
	}
	if len(secretShares) != n {
		t.Fatalf("expected %d secret shares, got %d", n, len(secretShares))
	}

	for i := 0; i < n; i++ {
		if secretShares[i] == nil {
			t.Fatalf("secret share %d is nil", i)
		}
	}
}

func TestHostKeyMismatch(t *testing.T) {
	_, pubkeys := generateHostKeys(3)
	wrongSk, _, _ := GenerateHostKey()

	params := &SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   2,
	}

	random := make([]byte, 32)
	rand.Read(random)

	_, _, err := ParticipantStep1(wrongSk, params, random)
	if err != ErrHostkeyMismatch {
		t.Fatalf("expected ErrHostkeyMismatch, got %v", err)
	}
}

func TestInvalidRandomness(t *testing.T) {
	seckeys, pubkeys := generateHostKeys(3)

	params := &SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   2,
	}

	_, _, err := ParticipantStep1(seckeys[0], params, []byte("short"))
	if err != ErrInvalidRandomness {
		t.Fatalf("expected ErrInvalidRandomness, got %v", err)
	}
}
