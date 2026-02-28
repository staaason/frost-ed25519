package communication

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type Handler struct {
	State *state.State
	Comm  Communicator
}

type SignHandler struct {
	*Handler
	Out *sign.Output
}

func (h *Handler) HandleMessage() {
	h.ProcessAll()

	for {
		select {
		case msg := <-h.Comm.Incoming():
			if msg == nil {
				continue
			}
			if err := h.State.HandleMessage(msg); err != nil {
			}
			h.ProcessAll()
		case <-h.State.Done():
			err := h.State.Err()
			if err != nil {
			}
			return
		}
	}
}

func (h *Handler) ProcessAll() {
	msgsOut := h.State.ProcessAll()

	for _, msg := range msgsOut {
		err := h.Comm.Send(msg)
		if err != nil {
			fmt.Println("process all", err)
		}
	}
}

func NewSignHandler(comm Communicator, IDs []party.ID, secret *eddsa.SecretShare, public *eddsa.Public, message []byte) (*SignHandler, error) {
	set := party.NewIDSlice(IDs)
	s, out, err := frost.NewSignState(set, secret, public, message, comm.Timeout())
	if err != nil {
		return nil, err
	}
	h := &Handler{
		State: s,
		Comm:  comm,
	}
	go h.HandleMessage()
	return &SignHandler{
		Handler: h,
		Out:     out,
	}, nil
}
