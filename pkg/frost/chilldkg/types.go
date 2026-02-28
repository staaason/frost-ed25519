package chilldkg

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type SessionParams struct {
	HostPubkeys []ristretto.Element
	Threshold   party.Size
}

type DKGOutput struct {
	SecShare        *ristretto.Scalar
	ThresholdPubkey ristretto.Element
	PubShares       []ristretto.Element
}

type RecoveryData struct {
	Data []byte
}

var (
	ErrInvalidHostSeckey        = errors.New("chilldkg: invalid host secret key")
	ErrInvalidHostPubkey        = errors.New("chilldkg: invalid host public key")
	ErrDuplicateHostPubkey      = errors.New("chilldkg: duplicate host public key")
	ErrThresholdOrCount         = errors.New("chilldkg: threshold/count out of range")
	ErrInvalidRandomness        = errors.New("chilldkg: invalid randomness length")
	ErrFaultyParticipant        = errors.New("chilldkg: faulty participant")
	ErrFaultyCoordinator        = errors.New("chilldkg: faulty coordinator")
	ErrFaultyParticipantOrCoord = errors.New("chilldkg: faulty participant or coordinator")
	ErrInvalidCertificate       = errors.New("chilldkg: invalid certificate signature")
	ErrInvalidRecoveryData      = errors.New("chilldkg: invalid recovery data")
	ErrInvalidShare             = errors.New("chilldkg: invalid secret share")
	ErrInvalidProofOfPossession = errors.New("chilldkg: invalid proof of possession")
	ErrMessageParse             = errors.New("chilldkg: message parse error")
	ErrHostkeyMismatch          = errors.New("chilldkg: host key does not match any participant")
)

type FaultyParticipantError struct {
	Index int
	Msg   string
}

func (e *FaultyParticipantError) Error() string {
	return e.Msg
}

func (e *FaultyParticipantError) Unwrap() error {
	return ErrFaultyParticipant
}
