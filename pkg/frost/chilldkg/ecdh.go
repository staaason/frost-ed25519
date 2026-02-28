package chilldkg

import (
	"encoding/binary"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func ecdhSharedSecret(seckey *ristretto.Scalar, theirPubkey *ristretto.Element) []byte {
	var shared ristretto.Element
	shared.ScalarMult(seckey, theirPubkey)
	return shared.Bytes()
}

func ecdhPad(seckey *ristretto.Scalar, myPubkey, theirPubkey *ristretto.Element, context []byte, sending bool) *ristretto.Scalar {
	shared := ecdhSharedSecret(seckey, theirPubkey)
	var data []byte
	data = append(data, shared...)
	if sending {
		data = append(data, myPubkey.Bytes()...)
		data = append(data, theirPubkey.Bytes()...)
	} else {
		data = append(data, theirPubkey.Bytes()...)
		data = append(data, myPubkey.Bytes()...)
	}
	data = append(data, context...)
	return taggedHashScalar("encpedpop ecdh", data)
}

func selfPad(symkey []byte, nonce *ristretto.Element, context []byte) *ristretto.Scalar {
	var data []byte
	data = append(data, symkey...)
	data = append(data, nonce.Bytes()...)
	data = append(data, context...)
	return taggedHashScalar("encaps_multi self_pad", data)
}

func encapsMulti(secnonce *ristretto.Scalar, pubnonce *ristretto.Element, deckey *ristretto.Scalar, enckeys []ristretto.Element, context []byte, idx int) []*ristretto.Scalar {
	pads := make([]*ristretto.Scalar, len(enckeys))
	for i := range enckeys {
		idxBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idxBytes, uint32(i))
		ctx := append(idxBytes, context...)

		if i == idx {
			pads[i] = selfPad(deckey.Bytes(), pubnonce, ctx)
		} else {
			pads[i] = ecdhPad(secnonce, pubnonce, &enckeys[i], ctx, true)
		}
	}
	return pads
}

func encryptMulti(secnonce *ristretto.Scalar, pubnonce *ristretto.Element, deckey *ristretto.Scalar, enckeys []ristretto.Element, context []byte, idx int, plaintexts []*ristretto.Scalar) []*ristretto.Scalar {
	pads := encapsMulti(secnonce, pubnonce, deckey, enckeys, context, idx)
	ciphertexts := make([]*ristretto.Scalar, len(plaintexts))
	for i := range plaintexts {
		var ct ristretto.Scalar
		ct.Add(plaintexts[i], pads[i])
		ciphertexts[i] = &ct
	}
	return ciphertexts
}

func decapsMulti(deckey *ristretto.Scalar, enckey *ristretto.Element, pubnonces []ristretto.Element, context []byte, idx int) []*ristretto.Scalar {
	idxBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBytes, uint32(idx))
	ctx := append(idxBytes, context...)

	pads := make([]*ristretto.Scalar, len(pubnonces))
	for senderIdx := range pubnonces {
		if senderIdx == idx {
			pads[senderIdx] = selfPad(deckey.Bytes(), &pubnonces[senderIdx], ctx)
		} else {
			pads[senderIdx] = ecdhPad(deckey, enckey, &pubnonces[senderIdx], ctx, false)
		}
	}
	return pads
}

func decryptSum(deckey *ristretto.Scalar, enckey *ristretto.Element, pubnonces []ristretto.Element, context []byte, idx int, sumCiphertext *ristretto.Scalar) *ristretto.Scalar {
	pads := decapsMulti(deckey, enckey, pubnonces, context, idx)
	var sumPads ristretto.Scalar
	sumPads.Set(ristretto.NewScalar())
	for _, pad := range pads {
		sumPads.Add(&sumPads, pad)
	}
	var result ristretto.Scalar
	result.Subtract(sumCiphertext, &sumPads)
	return &result
}
