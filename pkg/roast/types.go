package roast

import (
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type PreSignatureShare struct {
	Di, Ei ristretto.Element
}

type NonceState struct {
	D, E ristretto.Scalar
}
