package r43x6

// Reduced constants copied from Firedancer's r43x6 representation
// (https://github.com/firedancer-io/firedancer, Copyright 2022 Firedancer
// Contributors, Apache License 2.0) and converted from its C source form into
// Go limb literals. This notice is the change notice required by Apache-2.0
// section 4(b); see the NOTICE file for the section 4(d) attributions that
// accompany this material.
//
// Keeping them in limb form also checks that the scalar reference and a future
// SIMD backend agree on the representation boundary.
var (
	curveD = Element{limbs: Limbs{
		6365466163363, 253762649449, 7518893317,
		260847760460, 7696165686388, 704489577558,
	}}
	curve2D = Element{limbs: Limbs{
		3934839304537, 507525298899, 15037786634,
		521695520920, 6596238350568, 309467527341,
	}}
	sqrtM1 = Element{limbs: Limbs{
		3467281080496, 6582290652611, 5210002954932,
		329084955603, 4526638806224, 373767602335,
	}}
)
