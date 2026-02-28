package chilldkg

import (
	"encoding/binary"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type vssPolynomial struct {
	coeffs []ristretto.Scalar
}

type vssCommitment struct {
	points []ristretto.Element
}

func vssGenerate(seed []byte, t int) *vssPolynomial {
	coeffs := make([]ristretto.Scalar, t)
	for i := 0; i < t; i++ {
		iBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(iBytes, uint32(i))
		s := taggedHashScalar("vss coeffs", seed, iBytes)
		coeffs[i].Set(s)
	}
	return &vssPolynomial{coeffs: coeffs}
}

func (p *vssPolynomial) eval(x *ristretto.Scalar) *ristretto.Scalar {
	var value ristretto.Scalar
	value.Set(ristretto.NewScalar())
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		value.Multiply(&value, x)
		value.Add(&value, &p.coeffs[i])
	}
	return &value
}

func (p *vssPolynomial) secret() *ristretto.Scalar {
	var s ristretto.Scalar
	s.Set(&p.coeffs[0])
	return &s
}

func (p *vssPolynomial) secshares(n int) []*ristretto.Scalar {
	shares := make([]*ristretto.Scalar, n)
	for i := 0; i < n; i++ {
		idx := scalarFromUint32(uint32(i + 1))
		shares[i] = p.eval(idx)
	}
	return shares
}

func (p *vssPolynomial) commit() *vssCommitment {
	points := make([]ristretto.Element, len(p.coeffs))
	for i := range p.coeffs {
		points[i].ScalarBaseMult(&p.coeffs[i])
	}
	return &vssCommitment{points: points}
}

func (c *vssCommitment) commitmentToSecret() *ristretto.Element {
	var r ristretto.Element
	r.Set(&c.points[0])
	return &r
}

func (c *vssCommitment) commitmentToNonconstTerms() []ristretto.Element {
	if len(c.points) <= 1 {
		return nil
	}
	out := make([]ristretto.Element, len(c.points)-1)
	for i := 1; i < len(c.points); i++ {
		out[i-1].Set(&c.points[i])
	}
	return out
}

func (c *vssCommitment) pubshare(i int) *ristretto.Element {
	x := uint32(i + 1)
	var result ristretto.Element
	result.Set(ristretto.NewIdentityElement())

	for j := len(c.points) - 1; j >= 0; j-- {
		xScalar := scalarFromUint32(x)
		result.ScalarMult(xScalar, &result)
		result.Add(&result, &c.points[j])
	}
	return &result
}

func (c *vssCommitment) toBytes() []byte {
	var data []byte
	for _, p := range c.points {
		data = append(data, p.Bytes()...)
	}
	return data
}

func vssCommitmentFromParts(comToSecret *ristretto.Element, nonconstTerms []ristretto.Element) *vssCommitment {
	points := make([]ristretto.Element, 1+len(nonconstTerms))
	points[0].Set(comToSecret)
	for i, p := range nonconstTerms {
		points[i+1].Set(&p)
	}
	return &vssCommitment{points: points}
}

func vssVerifySecshare(secshare *ristretto.Scalar, pubshare *ristretto.Element) bool {
	var actual ristretto.Element
	actual.ScalarBaseMult(secshare)
	return actual.Equal(pubshare) == 1
}

func scalarFromUint32(x uint32) *ristretto.Scalar {
	bytes := make([]byte, 32)
	bytes[0] = byte(x)
	bytes[1] = byte(x >> 8)
	bytes[2] = byte(x >> 16)
	bytes[3] = byte(x >> 24)
	var s ristretto.Scalar
	_, err := s.SetCanonicalBytes(bytes)
	if err != nil {
		panic("scalarFromUint32: invalid")
	}
	return &s
}
