package roast

import (
	"errors"
	"sync"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

var (
	ErrTooManyMalicious = errors.New("roast: too many malicious signers")
	ErrAlreadyComplete  = errors.New("roast: signing already complete")
	ErrSignerMalicious  = errors.New("roast: signer is known malicious")
	ErrUnsolicited      = errors.New("roast: unsolicited reply")
	ErrInvalidShare     = errors.New("roast: invalid signature share")
)

type SignRequest struct {
	SessionID uint32
	SignerSet party.IDSlice
	PreShares map[party.ID]*PreSignatureShare
	Message   []byte
}

type Coordinator struct {
	pk      *eddsa.Public
	n       int
	t       int
	message []byte

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

func NewCoordinator(pk *eddsa.Public, threshold party.Size, message []byte) *Coordinator {
	n := int(pk.PartyIDs.N())
	t := int(threshold) + 1

	return &Coordinator{
		pk:         pk,
		n:          n,
		t:          t,
		message:    message,
		responsive: make(map[party.ID]struct{}),
		malicious:  make(map[party.ID]struct{}),
		preShares:  make(map[party.ID]*PreSignatureShare),
		signerSID:  make(map[party.ID]uint32),
		sessions:   make(map[uint32]*Session),
	}
}

func (c *Coordinator) HandleResponse(from party.ID, sigShare *ristretto.Scalar, preShare *PreSignatureShare) (*eddsa.Signature, []*SignRequest, error) {
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

		if session.IsComplete(c.t) {
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

func (c *Coordinator) initiateSession() []*SignRequest {
	c.sidCounter++
	sid := c.sidCounter

	signerSet := make(party.IDSlice, 0, c.t)
	sessionPreShares := make(map[party.ID]*PreSignatureShare, c.t)

	for id := range c.responsive {
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
	for _, id := range signerSet {
		_ = id
		requests = append(requests, &SignRequest{
			SessionID: sid,
			SignerSet: signerSet,
			PreShares: sessionPreShares,
			Message:   c.message,
		})
	}

	return requests
}

func (c *Coordinator) markMalicious(id party.ID) {
	c.malicious[id] = struct{}{}
	delete(c.responsive, id)
	delete(c.preShares, id)
	delete(c.signerSID, id)
}

func (c *Coordinator) IsDone() bool {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.done
}

func (c *Coordinator) Signature() *eddsa.Signature {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.signature
}

func (c *Coordinator) SignerSetForSession(sid uint32) party.IDSlice {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if s, ok := c.sessions[sid]; ok {
		return s.SignerSet
	}
	return nil
}
