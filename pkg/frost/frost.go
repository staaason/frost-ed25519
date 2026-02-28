package frost

import (
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

// NewSignState returns a state.State which coordinates the multiple rounds.
// The second parameter is the output of the protocol and will be filled with the output once the protocol has finished executing.
// It is safe to use the output when State.WaitForError() returns nil.
func NewSignState(partyIDs party.IDSlice, secret *eddsa.SecretShare, shares *eddsa.Public, message []byte, timeout time.Duration) (*state.State, *sign.Output, error) {
	round, output, err := sign.NewRound(partyIDs, secret, shares, message)
	if err != nil {
		return nil, nil, err
	}
	s, _ := state.NewBaseState(round, timeout)

	return s, output, nil
}
