package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/chilldkg"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

const maxN = 100

func usage() {
	cmd := filepath.Base(os.Args[0])
	fmt.Printf("usage: %v t n\nwhere 0 < t < n < %v\n", cmd, maxN)
}

func main() {
	if len(os.Args) != 3 {
		usage()
		return
	}

	var err error
	var t int
	var n int

	t, err = strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println(err)
		usage()
		return
	}
	n, err = strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println(err)
		usage()
		return
	}
	if (n > maxN) || (t >= n) {
		usage()
		return
	}

	hostseckeys := make([]*ristretto.Scalar, n)
	hostpubkeys := make([]ristretto.Element, n)
	for i := 0; i < n; i++ {
		sk, pk, err := chilldkg.GenerateHostKey()
		if err != nil {
			fmt.Println(err)
			return
		}
		hostseckeys[i] = sk
		hostpubkeys[i] = *pk
	}

	params := &chilldkg.SessionParams{
		HostPubkeys: hostpubkeys,
		Threshold:   party.Size(t),
	}

	outputs, _, err := chilldkg.SimulateSession(hostseckeys, params)
	if err != nil {
		fmt.Println(err)
		return
	}

	public, secretShares, err := chilldkg.OutputToFROST(outputs, params)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Group Key:")
	groupKey := public.GroupKey
	fmt.Printf("  %x\n\n", groupKey.ToEd25519())

	secrets := make(map[party.ID]*eddsa.SecretShare, n)
	for i, ss := range secretShares {
		id := party.ID(i + 1)
		secrets[id] = ss
		sharePublic := public.Shares[id]
		fmt.Printf("Party %d:\n  secret: %x\n  public: %x\n", id, ss.Secret.Bytes(), sharePublic.Bytes())
	}

	type KeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
	}

	kgOutput := KeyGenOutput{
		Secrets: secrets,
		Shares:  public,
	}

	var jsonData []byte
	jsonData, err = json.MarshalIndent(kgOutput, "", " ")
	if err != nil {
		fmt.Println(err)
		return
	}

	filename := "keygenout.json"

	_ = ioutil.WriteFile(filename, jsonData, 0644)

	fmt.Printf("Success: output written to %v\n", filename)
}
