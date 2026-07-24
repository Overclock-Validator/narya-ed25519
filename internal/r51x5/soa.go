package r51x5

const (
	// X4Lanes is the number of independent signatures in ElementX4.
	X4Lanes = 4
	// X8Lanes is the number of independent signatures in ElementX8.
	X8Lanes = 8
)

// LimbsX4 is the raw [limb][lane] layout of an ElementX4. Each lane returned
// by ElementX4.Limbs is reduced; arbitrary LimbsX4 values need not be.
type LimbsX4 [5][X4Lanes]uint64

// LimbsX8 is the raw [limb][lane] layout of an ElementX8. Each lane returned
// by ElementX8.Limbs is reduced; arbitrary LimbsX8 values need not be.
type LimbsX8 [5][X8Lanes]uint64

// ElementX4 is four independent reduced field elements stored [limb][lane].
// Its zero value contains four zero elements.
type ElementX4 struct {
	limbs LimbsX4
}

// ElementX8 is eight independent reduced field elements stored [limb][lane].
// Its zero value contains eight zero elements.
type ElementX8 struct {
	limbs LimbsX8
}

// IsReducedX4 reports whether every lane is a reduced field element.
func IsReducedX4(l LimbsX4) bool {
	for lane := 0; lane < X4Lanes; lane++ {
		var scalar Limbs
		for limb := range scalar {
			scalar[limb] = l[limb][lane]
		}
		if !IsReduced(scalar) {
			return false
		}
	}
	return true
}

// IsReducedX8 reports whether every lane is a reduced field element.
func IsReducedX8(l LimbsX8) bool {
	for lane := 0; lane < X8Lanes; lane++ {
		var scalar Limbs
		for limb := range scalar {
			scalar[limb] = l[limb][lane]
		}
		if !IsReduced(scalar) {
			return false
		}
	}
	return true
}

// SetElements packs four scalar elements into z and returns z.
func (z *ElementX4) SetElements(x *[X4Lanes]Element) *ElementX4 {
	for lane := range x {
		z.SetLane(lane, &x[lane])
	}
	return z
}

// Elements returns all four lanes as scalar elements.
func (z *ElementX4) Elements() [X4Lanes]Element {
	var out [X4Lanes]Element
	for lane := range out {
		out[lane] = z.Lane(lane)
	}
	return out
}

// Lane returns a copy of lane. It panics if lane is outside [0,4).
func (z *ElementX4) Lane(lane int) Element {
	checkLane(lane, X4Lanes)
	var out Element
	for limb := range out.limbs {
		out.limbs[limb] = z.limbs[limb][lane]
	}
	return out
}

// Limbs returns a copy of z's [limb][lane] representation.
func (z *ElementX4) Limbs() LimbsX4 { return z.limbs }

// SetLane copies the reduced scalar x into lane and returns z. It panics if
// lane is outside [0,4).
func (z *ElementX4) SetLane(lane int, x *Element) *ElementX4 {
	checkLane(lane, X4Lanes)
	for limb := range x.limbs {
		z.limbs[limb][lane] = x.limbs[limb]
	}
	return z
}

// Add sets z = x + y lane-wise and returns z. Inputs and output may alias.
func (z *ElementX4) Add(x, y *ElementX4) *ElementX4 {
	for lane := 0; lane < X4Lanes; lane++ {
		xl, yl := x.Lane(lane), y.Lane(lane)
		var out Element
		out.Add(&xl, &yl)
		z.SetLane(lane, &out)
	}
	return z
}

// Subtract sets z = x - y lane-wise and returns z.
func (z *ElementX4) Subtract(x, y *ElementX4) *ElementX4 {
	for lane := 0; lane < X4Lanes; lane++ {
		xl, yl := x.Lane(lane), y.Lane(lane)
		var out Element
		out.Subtract(&xl, &yl)
		z.SetLane(lane, &out)
	}
	return z
}

// Negate sets z = -x lane-wise and returns z.
func (z *ElementX4) Negate(x *ElementX4) *ElementX4 {
	for lane := 0; lane < X4Lanes; lane++ {
		xl := x.Lane(lane)
		var out Element
		out.Negate(&xl)
		z.SetLane(lane, &out)
	}
	return z
}

// Multiply sets z = x*y lane-wise and returns z.
func (z *ElementX4) Multiply(x, y *ElementX4) *ElementX4 {
	for lane := 0; lane < X4Lanes; lane++ {
		xl, yl := x.Lane(lane), y.Lane(lane)
		var out Element
		out.Multiply(&xl, &yl)
		z.SetLane(lane, &out)
	}
	return z
}

// Square sets z = x^2 lane-wise and returns z.
func (z *ElementX4) Square(x *ElementX4) *ElementX4 {
	for lane := 0; lane < X4Lanes; lane++ {
		xl := x.Lane(lane)
		var out Element
		out.Square(&xl)
		z.SetLane(lane, &out)
	}
	return z
}

// Invert sets z = 1/x lane-wise and returns z. Zero lanes remain zero.
func (z *ElementX4) Invert(x *ElementX4) *ElementX4 {
	for lane := 0; lane < X4Lanes; lane++ {
		xl := x.Lane(lane)
		var out Element
		out.Invert(&xl)
		z.SetLane(lane, &out)
	}
	return z
}

// SetElements packs eight scalar elements into z and returns z.
func (z *ElementX8) SetElements(x *[X8Lanes]Element) *ElementX8 {
	for lane := range x {
		z.SetLane(lane, &x[lane])
	}
	return z
}

// Elements returns all eight lanes as scalar elements.
func (z *ElementX8) Elements() [X8Lanes]Element {
	var out [X8Lanes]Element
	for lane := range out {
		out[lane] = z.Lane(lane)
	}
	return out
}

// Lane returns a copy of lane. It panics if lane is outside [0,8).
func (z *ElementX8) Lane(lane int) Element {
	checkLane(lane, X8Lanes)
	var out Element
	for limb := range out.limbs {
		out.limbs[limb] = z.limbs[limb][lane]
	}
	return out
}

// Limbs returns a copy of z's [limb][lane] representation.
func (z *ElementX8) Limbs() LimbsX8 { return z.limbs }

// SetLane copies the reduced scalar x into lane and returns z. It panics if
// lane is outside [0,8).
func (z *ElementX8) SetLane(lane int, x *Element) *ElementX8 {
	checkLane(lane, X8Lanes)
	for limb := range x.limbs {
		z.limbs[limb][lane] = x.limbs[limb]
	}
	return z
}

// Add sets z = x + y lane-wise and returns z. Inputs and output may alias.
func (z *ElementX8) Add(x, y *ElementX8) *ElementX8 {
	for lane := 0; lane < X8Lanes; lane++ {
		xl, yl := x.Lane(lane), y.Lane(lane)
		var out Element
		out.Add(&xl, &yl)
		z.SetLane(lane, &out)
	}
	return z
}

// Subtract sets z = x - y lane-wise and returns z.
func (z *ElementX8) Subtract(x, y *ElementX8) *ElementX8 {
	for lane := 0; lane < X8Lanes; lane++ {
		xl, yl := x.Lane(lane), y.Lane(lane)
		var out Element
		out.Subtract(&xl, &yl)
		z.SetLane(lane, &out)
	}
	return z
}

// Negate sets z = -x lane-wise and returns z.
func (z *ElementX8) Negate(x *ElementX8) *ElementX8 {
	for lane := 0; lane < X8Lanes; lane++ {
		xl := x.Lane(lane)
		var out Element
		out.Negate(&xl)
		z.SetLane(lane, &out)
	}
	return z
}

// Multiply sets z = x*y lane-wise and returns z.
func (z *ElementX8) Multiply(x, y *ElementX8) *ElementX8 {
	for lane := 0; lane < X8Lanes; lane++ {
		xl, yl := x.Lane(lane), y.Lane(lane)
		var out Element
		out.Multiply(&xl, &yl)
		z.SetLane(lane, &out)
	}
	return z
}

// Square sets z = x^2 lane-wise and returns z.
func (z *ElementX8) Square(x *ElementX8) *ElementX8 {
	for lane := 0; lane < X8Lanes; lane++ {
		xl := x.Lane(lane)
		var out Element
		out.Square(&xl)
		z.SetLane(lane, &out)
	}
	return z
}

// Invert sets z = 1/x lane-wise and returns z. Zero lanes remain zero.
func (z *ElementX8) Invert(x *ElementX8) *ElementX8 {
	for lane := 0; lane < X8Lanes; lane++ {
		xl := x.Lane(lane)
		var out Element
		out.Invert(&xl)
		z.SetLane(lane, &out)
	}
	return z
}

func checkLane(lane, width int) {
	if lane < 0 || lane >= width {
		panic("r51x5: lane index out of range")
	}
}
