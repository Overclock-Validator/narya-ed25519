package cpufeat

import "testing"

func TestX86FamilyFromVersion(t *testing.T) {
	for _, test := range []struct {
		name    string
		version uint32
		want    uint32
	}{
		{name: "ordinary-family", version: 0x00000600, want: 0x06},
		{name: "zen4-family-19h", version: 0x00a00f00, want: 0x19},
		{name: "zen5-family-1ah", version: 0x00b00f00, want: 0x1a},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := x86FamilyFromVersion(test.version); got != test.want {
				t.Fatalf("family=%#x want=%#x version=%#x", got, test.want, test.version)
			}
		})
	}
}

func TestRawSquareForAMDVersion(t *testing.T) {
	for _, test := range []struct {
		name   string
		ifma   bool
		family uint32
		want   bool
	}{
		{name: "zen4", ifma: true, family: 0x19, want: true},
		{name: "zen5", ifma: true, family: 0x1a, want: true},
		{name: "zen4-without-ifma", ifma: false, family: 0x19, want: false},
		{name: "zen5-without-ifma", ifma: false, family: 0x1a, want: false},
		{name: "unmeasured-future-family", ifma: true, family: 0x1b, want: false},
		{name: "non-amd", ifma: true, family: 0, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := rawSquareForAMDVersion(test.ifma, test.family); got != test.want {
				t.Fatalf("raw-square=%v want=%v ifma=%v family=%#x", got, test.want, test.ifma, test.family)
			}
		})
	}
}

func TestWideHashX4ForAMDVersion(t *testing.T) {
	for _, test := range []struct {
		name   string
		ifma   bool
		family uint32
		want   bool
	}{
		{name: "zen4", ifma: true, family: 0x19, want: false},
		{name: "zen5", ifma: true, family: 0x1a, want: true},
		{name: "zen5-without-ifma", ifma: false, family: 0x1a, want: false},
		{name: "non-amd", ifma: true, family: 0, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := wideHashX4ForAMDVersion(test.ifma, test.family); got != test.want {
				t.Fatalf("wide-hash-x4=%v want=%v ifma=%v family=%#x", got, test.want, test.ifma, test.family)
			}
		})
	}
}

func TestBatchEncodeX8ForAMDVersion(t *testing.T) {
	for _, test := range []struct {
		name   string
		ifma   bool
		family uint32
		want   bool
	}{
		{name: "zen4", ifma: true, family: 0x19, want: false},
		{name: "zen5", ifma: true, family: 0x1a, want: true},
		{name: "zen5-without-ifma", ifma: false, family: 0x1a, want: false},
		{name: "unmeasured-future-family", ifma: true, family: 0x1b, want: false},
		{name: "non-amd", ifma: true, family: 0, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := batchEncodeX8ForAMDVersion(test.ifma, test.family); got != test.want {
				t.Fatalf("batch-encode-x8=%v want=%v ifma=%v family=%#x", got, test.want, test.ifma, test.family)
			}
		})
	}
}

func TestProjectiveDoubleX8ForAMDVersion(t *testing.T) {
	for _, test := range []struct {
		name   string
		ifma   bool
		family uint32
		want   bool
	}{
		{name: "zen4", ifma: true, family: 0x19, want: false},
		{name: "zen5", ifma: true, family: 0x1a, want: true},
		{name: "zen5-without-ifma", ifma: false, family: 0x1a, want: false},
		{name: "unmeasured-future-family", ifma: true, family: 0x1b, want: false},
		{name: "non-amd", ifma: true, family: 0, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := projectiveDoubleX8ForAMDVersion(test.ifma, test.family); got != test.want {
				t.Fatalf("projective-double-x8=%v want=%v ifma=%v family=%#x", got, test.want, test.ifma, test.family)
			}
		})
	}
}

func TestAsymmetricFixedB10X8ForAMDVersion(t *testing.T) {
	for _, test := range []struct {
		name   string
		ifma   bool
		family uint32
		want   bool
	}{
		{name: "zen4", ifma: true, family: 0x19, want: false},
		{name: "zen5", ifma: true, family: 0x1a, want: true},
		{name: "zen5-without-ifma", ifma: false, family: 0x1a, want: false},
		{name: "unmeasured-future-family", ifma: true, family: 0x1b, want: false},
		{name: "non-amd", ifma: true, family: 0, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := asymmetricFixedB10X8ForAMDVersion(test.ifma, test.family); got != test.want {
				t.Fatalf("asymmetric-fixed-b10-x8=%v want=%v ifma=%v family=%#x", got, test.want, test.ifma, test.family)
			}
		})
	}
}

func TestNativeScalarReduceX8ForAMDVersion(t *testing.T) {
	for _, test := range []struct {
		name   string
		ifma   bool
		family uint32
		want   bool
	}{
		{name: "zen4", ifma: true, family: 0x19, want: false},
		{name: "zen5", ifma: true, family: 0x1a, want: true},
		{name: "zen5-without-ifma", ifma: false, family: 0x1a, want: false},
		{name: "unmeasured-future-family", ifma: true, family: 0x1b, want: false},
		{name: "non-amd", ifma: true, family: 0, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := nativeScalarReduceX8ForAMDVersion(test.ifma, test.family); got != test.want {
				t.Fatalf("native-scalar-reduce-x8=%v want=%v ifma=%v family=%#x", got, test.want, test.ifma, test.family)
			}
		})
	}
}

func TestPackedMul19X4ForAMDVersion(t *testing.T) {
	for _, test := range []struct {
		name   string
		ifma   bool
		family uint32
		want   bool
	}{
		{name: "zen4", ifma: true, family: 0x19, want: false},
		{name: "zen5", ifma: true, family: 0x1a, want: true},
		{name: "zen5-without-ifma", ifma: false, family: 0x1a, want: false},
		{name: "unmeasured-future-family", ifma: true, family: 0x1b, want: false},
		{name: "non-amd", ifma: true, family: 0, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := packedMul19X4ForAMDVersion(test.ifma, test.family); got != test.want {
				t.Fatalf("packed-mul19-x4=%v want=%v ifma=%v family=%#x", got, test.want, test.ifma, test.family)
			}
		})
	}
}
