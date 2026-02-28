package main

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/chilldkg"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/test/internal/communication"
)

func Setup(N, T party.Size) (message []byte, keygenIDs, signIDs []party.ID) {
	message = []byte("hello")
	keygenIDs = make([]party.ID, 0, N)
	for id := party.Size(0); id < N; id++ {
		keygenIDs = append(keygenIDs, 42+id)
	}
	signIDs = make([]party.ID, T+1)
	copy(signIDs, keygenIDs)
	return
}

func DoKeygen(N, T party.Size, keygenIDs []party.ID) (*eddsa.Public, map[party.ID]*eddsa.SecretShare, error) {
	n := int(N)
	seckeys := make([]*ristretto.Scalar, n)
	pubkeys := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		sk, pk, err := chilldkg.GenerateHostKey()
		if err != nil {
			return nil, nil, err
		}
		seckeys[i] = sk
		pubkeys[i] = *pk
	}

	params := &chilldkg.SessionParams{
		HostPubkeys: pubkeys,
		Threshold:   T,
	}

	outputs, _, err := chilldkg.SimulateSession(seckeys, params)
	if err != nil {
		return nil, nil, err
	}

	secrets := map[party.ID]*eddsa.SecretShare{}
	for i := 0; i < n; i++ {
		secrets[keygenIDs[i]] = eddsa.NewSecretShare(keygenIDs[i], outputs[i].SecShare)
	}

	partyShares := make(map[party.ID]*ristretto.Element, n)
	for i := 0; i < n; i++ {
		var pub ristretto.Element
		pub.ScalarBaseMult(outputs[i].SecShare)
		partyShares[keygenIDs[i]] = &pub
	}
	public, err := eddsa.NewPublic(partyShares, T)
	if err != nil {
		return nil, nil, err
	}

	return public, secrets, nil
}

func DoSign(T party.Size, signIDs []party.ID, shares *eddsa.Public, secrets map[party.ID]*eddsa.SecretShare, signComm map[party.ID]communication.Communicator, message []byte) error {
	groupKey := shares.GroupKey
	signHandlers := make(map[party.ID]*communication.SignHandler, T+1)
	var err error
	for _, id := range signIDs {
		signHandlers[id], err = communication.NewSignHandler(signComm[id], signIDs, secrets[id], shares, message)
		if err != nil {
			return err
		}
	}

	failures := 0

	for _, h := range signHandlers {
		err = h.State.WaitForError()
		if err != nil {
			failures++
		} else if s := h.Out.Signature; s != nil {
			if !groupKey.Verify(message, s) || !ed25519.Verify(groupKey.ToEd25519(), message, s.ToEd25519()) {
				failures++
			}
		}
	}

	if failures != 0 {
		return fmt.Errorf("%v signatures verifications failed", failures)
	}
	return nil
}

func FROSTestUDP(N, T party.Size) error {
	fmt.Printf("Using UDP:\n(n, t) = (%v, %v): ", N, T)

	message, keygenIDs, signIDs := Setup(N, T)
	shares, secrets, err := DoKeygen(N, T, keygenIDs)
	if err != nil {
		return err
	}

	signComm := communication.NewUDPCommunicatorMap(signIDs)
	defer destroyCommMap(signComm)

	return DoSign(T, signIDs, shares, secrets, signComm, message)
}

func FROSTestChannel(N, T party.Size) error {
	fmt.Printf("Using Channels:\n(n, t) = (%v, %v): ", N, T)

	message, keygenIDs, signIDs := Setup(N, T)
	shares, secrets, err := DoKeygen(N, T, keygenIDs)
	if err != nil {
		return err
	}

	signComm := communication.NewChannelCommunicatorMap(signIDs)
	defer destroyCommMap(signComm)

	return DoSign(T, signIDs, shares, secrets, signComm, message)
}

func destroyCommMap(m map[party.ID]communication.Communicator) {
	for _, c := range m {
		c.Done()
	}
}

func main() {
	ns := []party.Size{5, 10, 50}

	for _, n := range ns {
		start := time.Now()
		err := FROSTestUDP(n, n/2)
		elapsed := time.Since(start)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		fmt.Printf("%s\n", elapsed)

		start = time.Now()
		err = FROSTestUDP(n, n-1)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		elapsed = time.Since(start)
		fmt.Printf("%s\n", elapsed)

		start = time.Now()
		err = FROSTestChannel(n, n/2)
		elapsed = time.Since(start)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		fmt.Printf("%s\n", elapsed)

		start = time.Now()
		err = FROSTestChannel(n, n-1)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		elapsed = time.Since(start)
		fmt.Printf("%s\n", elapsed)
	}

	for _, n := range ns {
		if FROSTestUDP(n, n) == nil {
			fmt.Println("ERROR: failed to fail")
		} else {
			fmt.Println("ok (failed)")
		}
		if FROSTestUDP(n, 0) == nil {
			fmt.Println("ERROR: failed to fail")
		} else {
			fmt.Println("ok (failed)")
		}
		if FROSTestUDP(n, n*10) == nil {
			fmt.Println("ERROR: failed to fail")
		} else {
			fmt.Println("ok (failed)")
		}
	}
}
