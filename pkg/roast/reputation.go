package roast

import (
	"errors"
	"math"
	"sort"
	"sync"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

var (
	ErrInvalidGamma = errors.New("roast: gamma must be in (0, 1)")
	ErrInvalidDelta = errors.New("roast: delta_plus must be positive")
	ErrInvalidWMax  = errors.New("roast: w_max must be >= w0")
	ErrInvalidW0    = errors.New("roast: w0 must be positive")
)

type ReputationConfig struct {
	W0       float64
	WMax     float64
	DeltaPos float64
	Gamma    float64
}

func DefaultReputationConfig() ReputationConfig {
	return ReputationConfig{
		W0:       1.0,
		WMax:     3.0,
		DeltaPos: 0.5,
		Gamma:    0.8,
	}
}

func (c ReputationConfig) Validate() error {
	if c.Gamma <= 0 || c.Gamma >= 1 {
		return ErrInvalidGamma
	}
	if c.DeltaPos <= 0 {
		return ErrInvalidDelta
	}
	if c.W0 <= 0 {
		return ErrInvalidW0
	}
	if c.WMax < c.W0 {
		return ErrInvalidWMax
	}
	return nil
}

type ReputationCoordinator struct {
	pk      *eddsa.Public
	n       int
	t       int
	message []byte

	config  ReputationConfig
	weights map[party.ID]float64

	responsive map[party.ID]struct{}
	malicious  map[party.ID]struct{}
	preShares  map[party.ID]*PreSignatureShare
	signerSID  map[party.ID]uint32
	sessions   map[uint32]*Session
	sidCounter uint32

	signature *eddsa.Signature
	done      bool

	mtx sync.Mutex
}

func NewReputationCoordinator(pk *eddsa.Public, threshold party.Size, message []byte, config ReputationConfig) (*ReputationCoordinator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	n := int(pk.PartyIDs.N())
	t := int(threshold) + 1

	weights := make(map[party.ID]float64, n)
	for _, id := range pk.PartyIDs {
		weights[id] = config.W0
	}

	return &ReputationCoordinator{
		pk:         pk,
		n:          n,
		t:          t,
		message:    message,
		config:     config,
		weights:    weights,
		responsive: make(map[party.ID]struct{}),
		malicious:  make(map[party.ID]struct{}),
		preShares:  make(map[party.ID]*PreSignatureShare),
		signerSID:  make(map[party.ID]uint32),
		sessions:   make(map[uint32]*Session),
	}, nil
}

func (c *ReputationCoordinator) HandleResponse(from party.ID, sigShare *ristretto.Scalar, preShare *PreSignatureShare) (*eddsa.Signature, []*SignRequest, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.done {
		return c.signature, nil, ErrAlreadyComplete
	}

	if _, isMalicious := c.malicious[from]; isMalicious {
		return nil, nil, ErrSignerMalicious
	}

	if _, isResponsive := c.responsive[from]; isResponsive {
		c.markMalicious(from)
		return nil, nil, ErrUnsolicited
	}

	if sid, hasSID := c.signerSID[from]; hasSID {
		session := c.sessions[sid]
		if sigShare == nil {
			c.markMalicious(from)
			return nil, nil, ErrInvalidShare
		}

		if !session.ValidateAndStore(c.pk, from, sigShare) {
			c.markMalicious(from)
			return nil, nil, ErrInvalidShare
		}

		c.reward(from)

		if session.IsComplete(c.t) {
			c.decayNonParticipants(session.SignerSet)
			sig := SignAgg(&session.AggregateNonce, session.SigShares)
			if c.pk.GroupKey.Verify(c.message, sig) {
				c.signature = sig
				c.done = true
				return sig, nil, nil
			}
		}
	}

	c.preShares[from] = preShare
	c.responsive[from] = struct{}{}
	delete(c.signerSID, from)

	var requests []*SignRequest
	if len(c.responsive) >= c.t {
		requests = c.initiateSession()
	}

	if len(c.malicious) > c.n-c.t {
		return nil, nil, ErrTooManyMalicious
	}

	return nil, requests, nil
}

func (c *ReputationCoordinator) initiateSession() []*SignRequest {
	c.sidCounter++
	sid := c.sidCounter

	candidates := make([]party.ID, 0, len(c.responsive))
	for id := range c.responsive {
		candidates = append(candidates, id)
	}
	sort.Slice(candidates, func(i, j int) bool {
		wi := c.weights[candidates[i]]
		wj := c.weights[candidates[j]]
		if wi != wj {
			return wi > wj
		}
		return candidates[i] < candidates[j]
	})

	signerSet := make(party.IDSlice, 0, c.t)
	sessionPreShares := make(map[party.ID]*PreSignatureShare, c.t)

	for _, id := range candidates {
		if len(signerSet) >= c.t {
			break
		}
		signerSet = append(signerSet, id)
		sessionPreShares[id] = c.preShares[id]
	}

	signerSet = party.NewIDSlice(signerSet)

	session := NewSession(sid, signerSet, sessionPreShares, c.pk, c.message)
	c.sessions[sid] = session

	for _, id := range signerSet {
		c.signerSID[id] = sid
		delete(c.responsive, id)
	}

	requests := make([]*SignRequest, 0, len(signerSet))
	for range signerSet {
		requests = append(requests, &SignRequest{
			SessionID: sid,
			SignerSet: signerSet,
			PreShares: sessionPreShares,
			Message:   c.message,
		})
	}

	return requests
}

func (c *ReputationCoordinator) reward(id party.ID) {
	w := c.weights[id] + c.config.DeltaPos
	c.weights[id] = math.Min(w, c.config.WMax)
}

func (c *ReputationCoordinator) markMalicious(id party.ID) {
	c.malicious[id] = struct{}{}
	c.weights[id] = 0
	delete(c.responsive, id)
	delete(c.preShares, id)
	delete(c.signerSID, id)
}

func (c *ReputationCoordinator) decayNonParticipants(participants party.IDSlice) {
	participantSet := make(map[party.ID]struct{}, len(participants))
	for _, id := range participants {
		participantSet[id] = struct{}{}
	}
	for id := range c.weights {
		if _, ok := participantSet[id]; ok {
			continue
		}
		if _, ok := c.malicious[id]; ok {
			continue
		}
		c.weights[id] *= c.config.Gamma
	}
}

func (c *ReputationCoordinator) Weight(id party.ID) float64 {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.weights[id]
}

func (c *ReputationCoordinator) IsDone() bool {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.done
}

func (c *ReputationCoordinator) Signature() *eddsa.Signature {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.signature
}

func (c *ReputationCoordinator) IsMalicious(id party.ID) bool {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	_, ok := c.malicious[id]
	return ok
}

func (c *ReputationCoordinator) MaliciousCount() int {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return len(c.malicious)
}
