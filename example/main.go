package example

import (
	"crypto/ed25519"
	"log"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/chilldkg"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

var messagesIn, messagesOut chan *messages.Message

func MessageRoutine(msgsIn, msgsOut chan *messages.Message, s *state.State) {
	for {
		select {
		case msg := <-msgsIn:
			if err := s.HandleMessage(msg); err != nil {
				log.Println("failed to handle message", err)
				continue
			}

			for _, msgOut := range s.ProcessAll() {
				msgsOut <- msgOut
			}

		case <-s.Done():
			err := s.WaitForError()
			if err != nil {
				log.Panicln("protocol aborted: ", err)
			}
			return
		}
	}
}

func main() {
	n := 4
	threshold := party.Size(2)

	seckeys := make([]*ristretto.Scalar, n)
	pubkeys := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		sk, pk, err := chilldkg.GenerateHostKey()
		if err != nil {
			panic(err)
		}
		seckeys[i] = sk
		pubkeys[i] = *pk
	}

	params := &chilldkg.SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   threshold,
	}

	outputs, _, err := chilldkg.SimulateSession(seckeys, params)
	if err != nil {
		panic(err)
	}

	public, secretSharesList, err := chilldkg.OutputToFROST(outputs, params)
	if err != nil {
		panic(err)
	}

	groupKey := public.GroupKey
	selfID := public.PartyIDs[0]
	secretShare := secretSharesList[0]

	message := []byte("example")

	signers := party.NewIDSlice([]party.ID{public.PartyIDs[0], public.PartyIDs[1], public.PartyIDs[2]})
	signState, signOutput, err := frost.NewSignState(signers, secretShare, public, message, 1*time.Second)
	if err != nil {
		panic(err)
	}
	_ = selfID

	go MessageRoutine(messagesIn, messagesOut, signState)

	err = signState.WaitForError()
	if err != nil {
	}

	groupSig := signOutput.Signature
	if !ed25519.Verify(groupKey.ToEd25519(), message, groupSig.ToEd25519()) {
		log.Println("failed to validate single signature")
	}
}
