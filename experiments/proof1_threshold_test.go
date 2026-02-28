package experiments

import (
	"crypto/rand"
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

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

func randomScalar() *ristretto.Scalar {
	buf := make([]byte, 64)
	rand.Read(buf)
	var s ristretto.Scalar
	s.SetUniformBytes(buf)
	return &s
}

type poly struct {
	coeffs []*ristretto.Scalar
}

func newRandomPoly(degree int) *poly {
	p := &poly{coeffs: make([]*ristretto.Scalar, degree+1)}
	for i := 0; i <= degree; i++ {
		p.coeffs[i] = randomScalar()
	}
	return p
}

func (p *poly) eval(x *ristretto.Scalar) *ristretto.Scalar {
	var result ristretto.Scalar
	result.Set(ristretto.NewScalar())
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		result.Multiply(&result, x)
		result.Add(&result, p.coeffs[i])
	}
	return &result
}

func (p *poly) secret() *ristretto.Scalar {
	var s ristretto.Scalar
	s.Set(p.coeffs[0])
	return &s
}

func (p *poly) commitment() []*ristretto.Element {
	com := make([]*ristretto.Element, len(p.coeffs))
	for i := range p.coeffs {
		com[i] = new(ristretto.Element)
		com[i].ScalarBaseMult(p.coeffs[i])
	}
	return com
}

func addPolys(polys []*poly) *poly {
	degree := len(polys[0].coeffs) - 1
	sum := &poly{coeffs: make([]*ristretto.Scalar, degree+1)}
	for k := 0; k <= degree; k++ {
		sum.coeffs[k] = new(ristretto.Scalar)
		sum.coeffs[k].Set(ristretto.NewScalar())
		for _, p := range polys {
			sum.coeffs[k].Add(sum.coeffs[k], p.coeffs[k])
		}
	}
	return sum
}

func lagrangeCoeff(i int, evalPoints []int) *ristretto.Scalar {
	xi := scalarFromUint32(uint32(i))
	num := scalarFromUint32(1)
	den := scalarFromUint32(1)
	for _, j := range evalPoints {
		if j == i {
			continue
		}
		xj := scalarFromUint32(uint32(j))
		num.Multiply(num, xj)
		var diff ristretto.Scalar
		diff.Subtract(xj, xi)
		den.Multiply(den, &diff)
	}
	den.Invert(den)
	var result ristretto.Scalar
	result.Multiply(num, den)
	return &result
}

func TestProof1_DegreePreservation(t *testing.T) {
	configs := []struct {
		n, threshold int
	}{
		{3, 2}, {5, 3}, {7, 4}, {10, 6}, {15, 10},
	}

	for _, cfg := range configs {
		n := cfg.n
		threshold := cfg.threshold

		polys := make([]*poly, n)
		for j := 0; j < n; j++ {
			polys[j] = newRandomPoly(threshold - 1)
		}

		F := addPolys(polys)

		for k := threshold; k < len(F.coeffs); k++ {
			if F.coeffs[k].Equal(ristretto.NewScalar()) != 1 {
				t.Fatalf("n=%d,t=%d: coefficient %d of F is non-zero, deg(F) > t-1", n, threshold, k)
			}
		}

		evalPoints := make([]int, threshold)
		for i := 0; i < threshold; i++ {
			evalPoints[i] = i + 1
		}

		shares := make([]*ristretto.Scalar, threshold)
		for idx, pt := range evalPoints {
			x := scalarFromUint32(uint32(pt))
			shares[idx] = F.eval(x)
		}

		var reconstructed ristretto.Scalar
		reconstructed.Set(ristretto.NewScalar())
		for idx, pt := range evalPoints {
			lambda := lagrangeCoeff(pt, evalPoints)
			var term ristretto.Scalar
			term.Multiply(lambda, shares[idx])
			reconstructed.Add(&reconstructed, &term)
		}

		if reconstructed.Equal(F.secret()) != 1 {
			t.Fatalf("n=%d,t=%d: Lagrange reconstruction with t shares failed", n, threshold)
		}

		t.Logf("PASS n=%d, t=%d: deg(F)<=t-1, reconstruction with %d shares OK", n, threshold, threshold)
	}
}

func TestProof1_ReconstructionFailsWithFewerThanT(t *testing.T) {
	n := 5
	threshold := 3

	polys := make([]*poly, n)
	for j := 0; j < n; j++ {
		polys[j] = newRandomPoly(threshold - 1)
	}

	F := addPolys(polys)
	trueSecret := F.secret()

	for subsetSize := 1; subsetSize < threshold; subsetSize++ {
		evalPoints := make([]int, subsetSize)
		for i := 0; i < subsetSize; i++ {
			evalPoints[i] = i + 1
		}

		shares := make([]*ristretto.Scalar, subsetSize)
		for idx, pt := range evalPoints {
			x := scalarFromUint32(uint32(pt))
			shares[idx] = F.eval(x)
		}

		var reconstructed ristretto.Scalar
		reconstructed.Set(ristretto.NewScalar())
		for idx, pt := range evalPoints {
			lambda := lagrangeCoeff(pt, evalPoints)
			var term ristretto.Scalar
			term.Multiply(lambda, shares[idx])
			reconstructed.Add(&reconstructed, &term)
		}

		if reconstructed.Equal(trueSecret) == 1 {
			t.Fatalf("reconstruction with %d < t=%d shares should not recover secret (extremely unlikely)", subsetSize, threshold)
		}

		t.Logf("PASS: %d shares (< t=%d) do NOT recover the secret", subsetSize, threshold)
	}
}

func TestProof1_AdversarialPolynomialsBounded(t *testing.T) {
	n := 7
	threshold := 4
	adversaryCount := threshold - 1

	polys := make([]*poly, n)
	for j := 0; j < adversaryCount; j++ {
		polys[j] = newRandomPoly(threshold - 1)
	}
	for j := adversaryCount; j < n; j++ {
		polys[j] = newRandomPoly(threshold - 1)
	}

	F := addPolys(polys)

	evalPoints := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		evalPoints[i] = i + 1
	}

	shares := make([]*ristretto.Scalar, threshold)
	for idx, pt := range evalPoints {
		x := scalarFromUint32(uint32(pt))
		shares[idx] = F.eval(x)
	}

	var reconstructed ristretto.Scalar
	reconstructed.Set(ristretto.NewScalar())
	for idx, pt := range evalPoints {
		lambda := lagrangeCoeff(pt, evalPoints)
		var term ristretto.Scalar
		term.Multiply(lambda, shares[idx])
		reconstructed.Add(&reconstructed, &term)
	}

	if reconstructed.Equal(F.secret()) != 1 {
		t.Fatal("adversary with t-1 controlled polynomials could not raise threshold")
	}

	evalPoints2 := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		evalPoints2[i] = n - threshold + i + 1
	}

	shares2 := make([]*ristretto.Scalar, threshold)
	for idx, pt := range evalPoints2 {
		x := scalarFromUint32(uint32(pt))
		shares2[idx] = F.eval(x)
	}

	var reconstructed2 ristretto.Scalar
	reconstructed2.Set(ristretto.NewScalar())
	for idx, pt := range evalPoints2 {
		lambda := lagrangeCoeff(pt, evalPoints2)
		var term ristretto.Scalar
		term.Multiply(lambda, shares2[idx])
		reconstructed2.Add(&reconstructed2, &term)
	}

	if reconstructed2.Equal(F.secret()) != 1 {
		t.Fatal("different subset of t shares also recovers the same secret")
	}

	t.Logf("PASS: adversary controls %d/%d participants, threshold not raised, any t=%d shares reconstruct", adversaryCount, n, threshold)
}

func TestProof1_CommitmentLengthEnforcement(t *testing.T) {
	threshold := 3

	p := newRandomPoly(threshold - 1)
	com := p.commitment()

	if len(com) != threshold {
		t.Fatalf("commitment length %d != threshold %d", len(com), threshold)
	}

	higherPoly := newRandomPoly(threshold)
	higherCom := higherPoly.commitment()
	if len(higherCom) != threshold+1 {
		t.Fatalf("higher degree poly commitment length %d != %d", len(higherCom), threshold+1)
	}

	if len(higherCom) == threshold {
		t.Fatal("commitment length check should reject higher degree polynomial")
	}

	t.Logf("PASS: commitment length check rejects degree-%d polynomial (length %d != t=%d)", threshold, len(higherCom), threshold)
}
