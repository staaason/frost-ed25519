package roast

import (
	"crypto/ed25519"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

func TestReputationConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config ReputationConfig
		err    error
	}{
		{"valid default", DefaultReputationConfig(), nil},
		{"gamma=0", ReputationConfig{1, 3, 0.5, 0}, ErrInvalidGamma},
		{"gamma=1", ReputationConfig{1, 3, 0.5, 1}, ErrInvalidGamma},
		{"gamma>1", ReputationConfig{1, 3, 0.5, 1.5}, ErrInvalidGamma},
		{"gamma<0", ReputationConfig{1, 3, 0.5, -0.1}, ErrInvalidGamma},
		{"delta=0", ReputationConfig{1, 3, 0, 0.8}, ErrInvalidDelta},
		{"delta<0", ReputationConfig{1, 3, -1, 0.8}, ErrInvalidDelta},
		{"w0=0", ReputationConfig{0, 3, 0.5, 0.8}, ErrInvalidW0},
		{"wmax<w0", ReputationConfig{5, 3, 0.5, 0.8}, ErrInvalidWMax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.err != nil {
				assert.Equal(t, tt.err, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReputationInitialWeights(t *testing.T) {
	n := party.Size(5)
	threshold := party.Size(2)
	message := []byte("test")

	partyIDs, _, publicShares := setupKeys(t, n, threshold)
	config := DefaultReputationConfig()

	coord, err := NewReputationCoordinator(publicShares, threshold, message, config)
	require.NoError(t, err)

	for _, id := range partyIDs {
		assert.Equal(t, config.W0, coord.Weight(id))
	}
}

func TestReputationHappyPath(t *testing.T) {
	n := party.Size(5)
	threshold := party.Size(2)
	message := []byte("reputation happy path")

	partyIDs, secretShares, publicShares := setupKeys(t, n, threshold)
	config := DefaultReputationConfig()

	coord, err := NewReputationCoordinator(publicShares, threshold, message, config)
	require.NoError(t, err)

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

	require.NotNil(t, finalSig)
	assert.True(t, publicShares.GroupKey.Verify(message, finalSig))
	assert.True(t, ed25519.Verify(publicShares.GroupKey.ToEd25519(), message, finalSig.ToEd25519()))
}

func TestReputationRewardUpdatesWeight(t *testing.T) {
	n := party.Size(5)
	threshold := party.Size(2)
	message := []byte("reward test")

	partyIDs, secretShares, publicShares := setupKeys(t, n, threshold)
	config := ReputationConfig{W0: 1.0, WMax: 5.0, DeltaPos: 1.0, Gamma: 0.8}

	coord, err := NewReputationCoordinator(publicShares, threshold, message, config)
	require.NoError(t, err)

	signers := make(map[party.ID]*Signer, n)
	for _, id := range partyIDs {
		signers[id] = NewSigner(secretShares[id], publicShares, message)
	}

	initialShares := make(map[party.ID]*PreSignatureShare, n)
	for _, id := range partyIDs {
		initialShares[id] = signers[id].Init()
	}

	pendingRequests := make(map[party.ID]*SignRequest)
	for _, id := range partyIDs {
		_, requests, err := coord.HandleResponse(id, nil, initialShares[id])
		require.NoError(t, err)
		if requests != nil {
			signerSet := requests[0].SignerSet
			for i, rid := range signerSet {
				pendingRequests[rid] = requests[i]
			}
		}
	}

	for id, req := range pendingRequests {
		signer := signers[id]
		sigShare, nextPreShare, sErr := signer.Sign(req.SignerSet, req.PreShares)
		require.NoError(t, sErr)

		_, _, hErr := coord.HandleResponse(id, sigShare, nextPreShare)
		if hErr != nil {
			continue
		}

		w := coord.Weight(id)
		assert.Greater(t, w, config.W0, "weight should increase after valid share")
	}
}

func TestReputationDecayNonParticipants(t *testing.T) {
	n := party.Size(5)
	threshold := party.Size(2)
	message := []byte("decay test")

	partyIDs, secretShares, publicShares := setupKeys(t, n, threshold)
	config := ReputationConfig{W0: 1.0, WMax: 5.0, DeltaPos: 0.5, Gamma: 0.5}

	coord, err := NewReputationCoordinator(publicShares, threshold, message, config)
	require.NoError(t, err)

	signers := make(map[party.ID]*Signer, n)
	for _, id := range partyIDs {
		signers[id] = NewSigner(secretShares[id], publicShares, message)
	}

	initialShares := make(map[party.ID]*PreSignatureShare, n)
	for _, id := range partyIDs {
		initialShares[id] = signers[id].Init()
	}

	pendingRequests := make(map[party.ID]*SignRequest)
	for _, id := range partyIDs {
		_, requests, err := coord.HandleResponse(id, nil, initialShares[id])
		require.NoError(t, err)
		if requests != nil {
			signerSet := requests[0].SignerSet
			for i, rid := range signerSet {
				pendingRequests[rid] = requests[i]
			}
		}
	}

	participants := make(map[party.ID]bool)
	for id := range pendingRequests {
		participants[id] = true
	}

	for id, req := range pendingRequests {
		signer := signers[id]
		sigShare, nextPreShare, sErr := signer.Sign(req.SignerSet, req.PreShares)
		require.NoError(t, sErr)
		coord.HandleResponse(id, sigShare, nextPreShare)
	}

	if coord.IsDone() {
		for _, id := range partyIDs {
			if participants[id] {
				continue
			}
			w := coord.Weight(id)
			assert.LessOrEqual(t, w, config.W0*config.Gamma+1e-9,
				"non-participant %d should have decayed weight", id)
		}
	}
}

func TestReputationMaliciousExclusion(t *testing.T) {
	n := party.Size(7)
	threshold := party.Size(3)
	message := []byte("malicious exclusion")

	partyIDs, secretShares, publicShares := setupKeys(t, n, threshold)
	config := DefaultReputationConfig()

	coord, err := NewReputationCoordinator(publicShares, threshold, message, config)
	require.NoError(t, err)

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
		require.NoError(t, err)
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
			sigShare, nextPreShare, sErr := signer.Sign(req.SignerSet, req.PreShares)
			require.NoError(t, sErr)

			sig, requests, hErr := coord.HandleResponse(id, sigShare, nextPreShare)
			if hErr != nil {
				continue
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

	require.NotNil(t, finalSig, "should produce signature despite malicious signers")
	assert.True(t, publicShares.GroupKey.Verify(message, finalSig))

	for id := range maliciousSet {
		w := coord.Weight(id)
		assert.LessOrEqual(t, w, config.W0,
			"malicious signer %d should have weight <= initial", id)
	}
}

func TestReputationWeightCappedAtWMax(t *testing.T) {
	n := party.Size(3)
	threshold := party.Size(1)
	message := []byte("cap test")

	_, _, publicShares := setupKeys(t, n, threshold)
	config := ReputationConfig{W0: 1.0, WMax: 2.0, DeltaPos: 5.0, Gamma: 0.9}

	coord, err := NewReputationCoordinator(publicShares, threshold, message, config)
	require.NoError(t, err)

	coord.mtx.Lock()
	coord.reward(publicShares.PartyIDs[0])
	w := coord.weights[publicShares.PartyIDs[0]]
	coord.mtx.Unlock()

	assert.Equal(t, config.WMax, w, "weight should be capped at WMax")
}

func TestReputationDecayConvergence(t *testing.T) {
	n := party.Size(3)
	threshold := party.Size(1)
	message := []byte("convergence test")

	_, _, publicShares := setupKeys(t, n, threshold)
	gamma := 0.8
	config := ReputationConfig{W0: 10.0, WMax: 10.0, DeltaPos: 0.5, Gamma: gamma}

	coord, err := NewReputationCoordinator(publicShares, threshold, message, config)
	require.NoError(t, err)

	id := publicShares.PartyIDs[0]
	emptyParticipants := party.IDSlice{}

	coord.mtx.Lock()
	for i := 0; i < 100; i++ {
		coord.decayNonParticipants(emptyParticipants)
	}
	w := coord.weights[id]
	coord.mtx.Unlock()

	expected := config.W0 * math.Pow(gamma, 100)
	assert.InDelta(t, expected, w, 1e-10, "weight should decay as gamma^k")
}

func TestReputationSleepingAgentBounded(t *testing.T) {
	n := party.Size(7)
	threshold := party.Size(3)
	message := []byte("sleeping agent")

	partyIDs, secretShares, publicShares := setupKeys(t, n, threshold)
	config := DefaultReputationConfig()

	coord, err := NewReputationCoordinator(publicShares, threshold, message, config)
	require.NoError(t, err)

	f := int(n) - int(threshold) - 1
	maliciousSet := make(map[party.ID]bool)
	for i := 0; i < f; i++ {
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
		sig, requests, hErr := coord.HandleResponse(id, nil, initialShares[id])
		require.NoError(t, hErr)
		if sig != nil {
			finalSig = sig
			break
		}
		if requests != nil {
			for i, rid := range requests[0].SignerSet {
				pendingRequests[rid] = requests[i]
			}
		}
	}

	maxRounds := int(n) + f
	for round := 0; finalSig == nil && round < maxRounds; round++ {
		newPending := make(map[party.ID]*SignRequest)
		for id, req := range pendingRequests {
			if maliciousSet[id] {
				continue
			}
			signer := signers[id]
			sigShare, nextPreShare, sErr := signer.Sign(req.SignerSet, req.PreShares)
			require.NoError(t, sErr)

			sig, requests, hErr := coord.HandleResponse(id, sigShare, nextPreShare)
			if hErr != nil {
				continue
			}
			if sig != nil {
				finalSig = sig
				break
			}
			if requests != nil {
				for i, rid := range requests[0].SignerSet {
					newPending[rid] = requests[i]
				}
			}
		}
		if finalSig != nil {
			break
		}
		pendingRequests = newPending
	}

	require.NotNil(t, finalSig)
	assert.True(t, publicShares.GroupKey.Verify(message, finalSig))
	assert.LessOrEqual(t, coord.MaliciousCount(), f,
		"total malicious identified should not exceed f")
}
