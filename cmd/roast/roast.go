package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/roast"
)

func usage() {
	cmd := filepath.Base(os.Args[0])
	fmt.Printf("usage: %v <JSON file> <message> [malicious_count]\n", cmd)
	fmt.Println("  JSON file:        keygen output from cmd/keygen")
	fmt.Println("  message:          message to sign")
	fmt.Println("  malicious_count:  optional number of simulated non-responsive signers (default: 0)")
}

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		usage()
		return
	}

	filename := os.Args[1]
	message := []byte(os.Args[2])

	maliciousCount := 0
	if len(os.Args) == 4 {
		var err error
		maliciousCount, err = strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Printf("invalid malicious_count: %v\n", err)
			usage()
			return
		}
	}

	type KeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
	}

	var kgOutput KeyGenOutput

	jsonData, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = json.Unmarshal(jsonData, &kgOutput)
	if err != nil {
		fmt.Println(err)
		return
	}

	n := kgOutput.Shares.PartyIDs.N()
	t := kgOutput.Shares.Threshold

	fmt.Printf("ROAST signing: (t, n) = (%v, %v), malicious = %v\n", t, n, maliciousCount)

	if maliciousCount > int(n)-int(t)-1 {
		fmt.Printf("error: too many malicious signers (%d), max allowed is %d\n", maliciousCount, int(n)-int(t)-1)
		return
	}

	partyIDs := kgOutput.Shares.PartyIDs
	secretShares := kgOutput.Secrets
	publicShares := kgOutput.Shares

	maliciousSet := make(map[party.ID]bool)
	for i := 0; i < maliciousCount; i++ {
		maliciousSet[partyIDs[i]] = true
	}

	coord := roast.NewCoordinator(publicShares, t, message)

	signers := make(map[party.ID]*roast.Signer, n)
	for _, id := range partyIDs {
		signers[id] = roast.NewSigner(secretShares[id], publicShares, message)
	}

	initialShares := make(map[party.ID]*roast.PreSignatureShare, n)
	for _, id := range partyIDs {
		initialShares[id] = signers[id].Init()
	}

	var finalSig *eddsa.Signature
	pendingRequests := make(map[party.ID]*roast.SignRequest)
	sessionCount := 0

	for _, id := range partyIDs {
		sig, requests, err := coord.HandleResponse(id, nil, initialShares[id])
		if err != nil {
			fmt.Printf("error: initial response from %d: %v\n", id, err)
			return
		}
		if sig != nil {
			finalSig = sig
			break
		}
		if requests != nil {
			sessionCount++
			fmt.Printf("  session %d initiated with %d signers\n", sessionCount, len(requests[0].SignerSet))
			signerSet := requests[0].SignerSet
			for i, rid := range signerSet {
				pendingRequests[rid] = requests[i]
			}
		}
	}

	maxRounds := int(n)
	for round := 0; finalSig == nil && round < maxRounds; round++ {
		newPending := make(map[party.ID]*roast.SignRequest)

		for id, req := range pendingRequests {
			if maliciousSet[id] {
				fmt.Printf("  signer %d is malicious, not responding\n", id)
				continue
			}

			signer := signers[id]
			sigShare, nextPreShare, err := signer.Sign(req.SignerSet, req.PreShares)
			if err != nil {
				fmt.Printf("error: signer %d failed to sign: %v\n", id, err)
				return
			}

			sig, requests, err := coord.HandleResponse(id, sigShare, nextPreShare)
			if err != nil {
				fmt.Printf("error: response from %d: %v\n", id, err)
				return
			}
			if sig != nil {
				finalSig = sig
				break
			}
			if requests != nil {
				sessionCount++
				fmt.Printf("  session %d initiated with %d signers\n", sessionCount, len(requests[0].SignerSet))
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
		fmt.Println("error: failed to produce a signature")
		return
	}

	pk := publicShares.GroupKey

	if !pk.Verify(message, finalSig) {
		fmt.Println("error: signature verification failed")
		return
	}

	if !ed25519.Verify(pk.ToEd25519(), message, finalSig.ToEd25519()) {
		fmt.Println("error: ed25519 signature verification failed")
		return
	}

	fmt.Printf("\nSuccess after %d session(s):\n", sessionCount)
	fmt.Printf("  r: %x\n", finalSig.R.Bytes())
	fmt.Printf("  s: %x\n", finalSig.S.Bytes())
}
