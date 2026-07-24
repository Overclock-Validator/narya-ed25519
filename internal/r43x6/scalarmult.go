package r43x6

import "sync"

type nafTable5 [8]Point
type nafTable8 [64]Point

func newNAFTable5(q *Point) nafTable5 {
	var table nafTable5
	table[0].Set(q)
	var twiceQ Point
	twiceQ.Double(q)
	for i := 0; i < len(table)-1; i++ {
		table[i+1].Add(&table[i], &twiceQ)
	}
	return table
}

func newNAFTable8(q *Point) nafTable8 {
	var table nafTable8
	table[0].Set(q)
	var twiceQ Point
	twiceQ.Double(q)
	for i := 0; i < len(table)-1; i++ {
		table[i+1].Add(&table[i], &twiceQ)
	}
	return table
}

var basepointNAF struct {
	once  sync.Once
	table nafTable8
}

func basepointNAFTable() *nafTable8 {
	basepointNAF.once.Do(func() {
		basepointNAF.table = newNAFTable8(NewGeneratorPoint())
	})
	return &basepointNAF.table
}

func selectNAF5(table *nafTable5, digit int8) Point {
	negative := digit < 0
	if negative {
		digit = -digit
	}
	result := table[digit/2]
	if negative {
		result.Negate(&result)
	}
	return result
}

func selectNAF8(table *nafTable8, digit int8) Point {
	negative := digit < 0
	if negative {
		digit = -digit
	}
	result := table[digit/2]
	if negative {
		result.Negate(&result)
	}
	return result
}

// VarTimeDoubleScalarBaseMult sets p = [a]A + [b]B, where B is the canonical
// generator. It uses a width-5 NAF table for A and a width-8 table for B,
// mirroring the existing generic verifier's model. This scalar implementation
// is a correctness reference, not a performance backend.
func (p *Point) VarTimeDoubleScalarBaseMult(a *Scalar, A *Point, b *Scalar) *Point {
	aTable := newNAFTable5(A)
	bTable := basepointNAFTable()
	aNAF := a.nonAdjacentForm(5)
	bNAF := b.nonAdjacentForm(8)

	acc := NewIdentityPoint()
	for i := 255; i >= 0; i-- {
		acc.Double(acc)
		if aNAF[i] != 0 {
			multiple := selectNAF5(&aTable, aNAF[i])
			acc.Add(acc, &multiple)
		}
		if bNAF[i] != 0 {
			multiple := selectNAF8(bTable, bNAF[i])
			acc.Add(acc, &multiple)
		}
	}
	*p = *acc
	return p
}

// VarTimeVerifyMult sets p = [s]B - [k]A, the cofactorless Ed25519
// verification equation's computed side.
func (p *Point) VarTimeVerifyMult(s, k *Scalar, A *Point) *Point {
	var minusA Point
	minusA.Negate(A)
	return p.VarTimeDoubleScalarBaseMult(k, &minusA, s)
}
