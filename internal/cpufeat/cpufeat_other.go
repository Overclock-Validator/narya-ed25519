//go:build !amd64

package cpufeat

var hasIFMA = false
var preferWideIFMA = false
var preferDecodedAIFMA = false
var preferWarmX8IFMA = false
var preferRawSquareIFMA = false
var preferWideHashX4IFMA = false
var preferBatchEncodeX8IFMA = false
var preferProjectiveDoubleX8IFMA = false
var preferAsymmetricFixedB10X8IFMA = false
var preferNativeScalarReduceX8IFMA = false
var preferPackedMul19X4IFMA = false
var preferPackedPairX8IFMA = false
