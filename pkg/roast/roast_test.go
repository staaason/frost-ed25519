package roast

import (
	"crypto/ed25519"
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func setupKeys(t *testing.T, n, threshold party.Size) (party.IDSlice, map[party.ID]*eddsa.SecretShare, *eddsa.Public) {
	partyIDs := helpers.GenerateSet(n)
	_, secretShares := helpers.GenerateSecrets(partyIDs, threshold)
	publicShares := helpers.GeneratePublic(threshold, secretShares)
	return partyIDs, secretShares, publicShares
}

func TestROASTHappyPath(t *testing.T) {
	n := party.Size(5)
	threshold := party.Size(2)
	message := []byte("hello roast")

	partyIDs, secretShares, publicShares := setupKeys(t, n, threshold)

	coord := NewCoordinator(publicShares, threshold, message)
	signers := make(map[party.ID]*Signer, n)
	for _, id := range partyIDs {
		signers[id] = NewSigner(secretShares[id], publicShares, message)
	}

	initialShares := make(map[party.ID]*PreSignatureShare, n)
	for _, id := range partyIDs {
		initialShares[id] = signers[id].Init()
	}

	var finalSig *eddsa.Signature

	pendingRequests := make(map[party.ID]*SignRequest)

	for _, id := range partyIDs {
		sig, requests, err := coord.HandleResponse(id, nil, initialShares[id])
		if err != nil {
			t.Fatalf("initial HandleResponse for %d: %v", id, err)
		}
		if sig != nil {
			finalSig = sig
			break
		}
		if requests != nil {
			signerSet := requests[0].SignerSet
			for i, rid := range signerSet {
				pendingRequests[rid] = requests[i]
			}
		}
	}

	for finalSig == nil {
		newPending := make(map[party.ID]*SignRequest)
		for id, req := range pendingRequests {
			signer := signers[id]
			sigShare, nextPreShare, err := signer.Sign(req.SignerSet, req.PreShares)
			if err != nil {
				t.Fatalf("signer %d sign: %v", id, err)
			}

			sig, requests, err := coord.HandleResponse(id, sigShare, nextPreShare)
			if err != nil {
				t.Fatalf("HandleResponse for %d: %v", id, err)
			}
			if sig != nil {
				finalSig = sig
				break
			}
			if requests != nil {
				signerSet := requests[0].SignerSet
				for i, rid := range signerSet {
					newPending[rid] = requests[i]
				}
			}
		}
		if finalSig != nil {
			break
		}
		pendingRequests = newPending
	}

	if finalSig == nil {
		t.Fatal("no signature produced")
	}
	if !publicShares.GroupKey.Verify(message, finalSig) {
		t.Fatal("signature verification failed (custom)")
	}
	if !ed25519.Verify(publicShares.GroupKey.ToEd25519(), message, finalSig.ToEd25519()) {
		t.Fatal("signature verification failed (ed25519)")
	}
}

func TestROASTWithMaliciousSigners(t *testing.T) {
	n := party.Size(7)
	threshold := party.Size(3)
	message := []byte("roast with malicious")

	partyIDs, secretShares, publicShares := setupKeys(t, n, threshold)

	coord := NewCoordinator(publicShares, threshold, message)

	maliciousCount := int(n) - int(threshold) - 1
	maliciousSet := make(map[party.ID]bool)
	for i := 0; i < maliciousCount; i++ {
		maliciousSet[partyIDs[i]] = true
	}

	signers := make(map[party.ID]*Signer, n)
	for _, id := range partyIDs {
		signers[id] = NewSigner(secretShares[id], publicShares, message)
	}

	initialShares := make(map[party.ID]*PreSignatureShare, n)
	for _, id := range partyIDs {
		initialShares[id] = signers[id].Init()
	}

	var finalSig *eddsa.Signature
	pendingRequests := make(map[party.ID]*SignRequest)

	for _, id := range partyIDs {
		sig, requests, err := coord.HandleResponse(id, nil, initialShares[id])
		if err != nil {
			t.Fatalf("initial HandleResponse for %d: %v", id, err)
		}
		if sig != nil {
			finalSig = sig
			break
		}
		if requests != nil {
			signerSet := requests[0].SignerSet
			for i, rid := range signerSet {
				pendingRequests[rid] = requests[i]
			}
		}
	}

	maxRounds := int(n)
	for round := 0; finalSig == nil && round < maxRounds; round++ {
		newPending := make(map[party.ID]*SignRequest)
		for id, req := range pendingRequests {
			if maliciousSet[id] {
				continue
			}

			signer := signers[id]
			sigShare, nextPreShare, err := signer.Sign(req.SignerSet, req.PreShares)
			if err != nil {
				t.Fatalf("signer %d sign: %v", id, err)
			}

			sig, requests, err := coord.HandleResponse(id, sigShare, nextPreShare)
			if err != nil {
				t.Fatalf("HandleResponse for %d: %v", id, err)
			}
			if sig != nil {
				finalSig = sig
				break
			}
			if requests != nil {
				signerSet := requests[0].SignerSet
				for i, rid := range signerSet {
					newPending[rid] = requests[i]
				}
			}
		}
		if finalSig != nil {
			break
		}
		pendingRequests = newPending
	}

	if finalSig == nil {
		t.Fatal("no signature produced despite having enough honest signers")
	}
	if !publicShares.GroupKey.Verify(message, finalSig) {
		t.Fatal("signature verification failed")
	}
}

func TestROASTLargeGroup(t *testing.T) {
	n := party.Size(15)
	threshold := party.Size(9)
	message := []byte("large group roast")

	partyIDs, secretShares, publicShares := setupKeys(t, n, threshold)

	coord := NewCoordinator(publicShares, threshold, message)
	signers := make(map[party.ID]*Signer, n)
	for _, id := range partyIDs {
		signers[id] = NewSigner(secretShares[id], publicShares, message)
	}

	initialShares := make(map[party.ID]*PreSignatureShare, n)
	for _, id := range partyIDs {
		initialShares[id] = signers[id].Init()
	}

	var finalSig *eddsa.Signature
	pendingRequests := make(map[party.ID]*SignRequest)

	for _, id := range partyIDs {
		sig, requests, err := coord.HandleResponse(id, nil, initialShares[id])
		if err != nil {
			t.Fatalf("initial HandleResponse for %d: %v", id, err)
		}
		if sig != nil {
			finalSig = sig
			break
		}
		if requests != nil {
			signerSet := requests[0].SignerSet
			for i, rid := range signerSet {
				pendingRequests[rid] = requests[i]
			}
		}
	}

	for finalSig == nil {
		newPending := make(map[party.ID]*SignRequest)
		for id, req := range pendingRequests {
			signer := signers[id]
			sigShare, nextPreShare, err := signer.Sign(req.SignerSet, req.PreShares)
			if err != nil {
				t.Fatalf("signer %d sign: %v", id, err)
			}

			sig, requests, err := coord.HandleResponse(id, sigShare, nextPreShare)
			if err != nil {
				t.Fatalf("HandleResponse for %d: %v", id, err)
			}
			if sig != nil {
				finalSig = sig
				break
			}
			if requests != nil {
				signerSet := requests[0].SignerSet
				for i, rid := range signerSet {
					newPending[rid] = requests[i]
				}
			}
		}
		if finalSig != nil {
			break
		}
		pendingRequests = newPending
	}

	if finalSig == nil {
		t.Fatal("no signature produced")
	}
	if !publicShares.GroupKey.Verify(message, finalSig) {
		t.Fatal("signature verification failed")
	}
	if !ed25519.Verify(publicShares.GroupKey.ToEd25519(), message, finalSig.ToEd25519()) {
		t.Fatal("ed25519 signature verification failed")
	}
}

func TestPreRoundAndShareVal(t *testing.T) {
	n := party.Size(3)
	threshold := party.Size(1)

	partyIDs, secretShares, publicShares := setupKeys(t, n, threshold)
	message := []byte("test shareval")

	signerSet := party.NewIDSlice(partyIDs[:threshold+1])

	preShares := make(map[party.ID]*PreSignatureShare, len(signerSet))
	nonceStates := make(map[party.ID]*NonceState, len(signerSet))
	for _, id := range signerSet {
		state, share := PreRound()
		nonceStates[id] = state
		preShares[id] = share
	}

	bindingFactors := ComputeBindingFactors(signerSet, preShares, message)
	nonceShares, aggregateNonce := ComputeNonceCommitments(signerSet, preShares, bindingFactors)
	challenge := eddsa.ComputeChallenge(aggregateNonce, publicShares.GroupKey, message)

	sigShares := make(map[party.ID]*ristretto.Scalar, len(signerSet))
	for _, id := range signerSet {
		sigShare, err := SignRound(secretShares[id], publicShares, signerSet, nonceStates[id], preShares, message)
		if err != nil {
			t.Fatalf("SignRound for %d: %v", id, err)
		}
		sigShares[id] = sigShare

		if !ShareVal(publicShares, signerSet, id, aggregateNonce, nonceShares[id], challenge, sigShare) {
			t.Fatalf("ShareVal failed for honest signer %d", id)
		}
	}

	sig := SignAgg(aggregateNonce, sigShares)
	if !publicShares.GroupKey.Verify(message, sig) {
		t.Fatal("aggregated signature verification failed")
	}
}
