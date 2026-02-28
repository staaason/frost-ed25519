package chilldkg

import (
	"encoding/binary"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func ParamsValidate(params *SessionParams) error {
	n := len(params.HostPubkeys)
	t := int(params.Threshold)

	if t < 1 || t > n || n > (1<<32)-1 {
		return ErrThresholdOrCount
	}

	seen := make(map[string]int)
	for i, pk := range params.HostPubkeys {
		b := pk.Bytes()
		key := string(b)
		if prevIdx, ok := seen[key]; ok {
			return fmt.Errorf("%w: indices %d and %d", ErrDuplicateHostPubkey, prevIdx, i)
		}
		seen[key] = i
	}

	return nil
}

func ParamsID(params *SessionParams) ([]byte, error) {
	if err := ParamsValidate(params); err != nil {
		return nil, err
	}

	tBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tBytes, uint32(params.Threshold))

	var data []byte
	data = append(data, tBytes...)
	for _, pk := range params.HostPubkeys {
		data = append(data, pk.Bytes()...)
	}

	return taggedHash("params_id", data), nil
}

func serializeEncContext(t int, enckeys []ristretto.Element) []byte {
	tBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tBytes, uint32(t))
	data := make([]byte, 0, 4+32*len(enckeys))
	data = append(data, tBytes...)
	for _, ek := range enckeys {
		data = append(data, ek.Bytes()...)
	}
	return data
}
