// Reduced constants derived from Firedancer's r43x6 representation at commit
// 3ed37488372b7e50bb03ca30477be48508ee7022.
// Copyright 2022 Firedancer Contributors. Licensed under Apache-2.0.
// Converted from C source form into Go limb literals by Overclock Validator;
// see the repository NOTICE for the Apache-2.0 change notice and inherited
// attribution.

package r43x6

// Source:
// https://github.com/firedancer-io/firedancer/blob/3ed37488372b7e50bb03ca30477be48508ee7022/src/ballet/ed25519/avx512/fd_r43x6.h
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
