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
