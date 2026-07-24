package sha512mb

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"testing"
)

// Hashing is the recurrence-independent part of every verification: k =
// H(R ‖ A ‖ M). This benchmark reports per-message cost for the scalar
// single-stream path (crypto/sha512) against the batch API, so once the
// AVX-512 multi-buffer kernel lands its win over the scalar loop is
// measured here directly. Message sizes span the prefix-only case up to
// the Solana packet cap; the 64-byte R‖A prefix is included.
func BenchmarkHash(b *testing.B) {
	for _, sz := range []int{0, 64, 176, 200, 512, 1024, 1232} {
		prefix := make([]byte, 64) // R (32) ‖ A (32)
		msg := make([]byte, sz)
		rand.Read(prefix)
		rand.Read(msg)

		b.Run(fmt.Sprintf("impl=crypto-sha512/msg=%d", sz), func(b *testing.B) {
			var out [64]byte
			for i := 0; i < b.N; i++ {
				h := sha512.New()
				h.Write(prefix)
				h.Write(msg)
				h.Sum(out[:0])
			}
		})

		lanes := Lanes()
		b.Run(fmt.Sprintf("impl=sha512mb-x%d/msg=%d", lanes, sz), func(b *testing.B) {
			out := make([][64]byte, lanes)
			batch := make([][][]byte, lanes)
			for i := range batch {
				batch[i] = [][]byte{prefix, msg}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Sum512Batch(out, batch)
			}
			// Per-message, so lanes are comparable to the scalar path.
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*lanes), "ns/msg")
		})
	}
}

// BenchmarkReferenceWidths compares the production scalar batch with the
// pure-Go x1/x4/x8 scheduling references. The timer includes segmented R/A/M
// packing, per-lane padding, scheduling, compression, and digest extraction.
// These results do not select production dispatch; they only establish a
// correctness-reference baseline.
func BenchmarkReferenceWidths(b *testing.B) {
	for _, messageSize := range []int{64, 176, 200, 512, 1024, 1232} {
		msgs := make([][][]byte, 8)
		var bytesPerBatch int64
		for lane := range msgs {
			r := make([]byte, 32)
			a := make([]byte, 32)
			message := make([]byte, messageSize)
			rand.Read(r)
			rand.Read(a)
			rand.Read(message)
			msgs[lane] = [][]byte{r, a, message}
			bytesPerBatch += int64(len(r) + len(a) + len(message))
		}
		implementations := []struct {
			name string
			fn   func([][64]byte, [][][]byte)
		}{
			{"production-x1", Sum512Batch},
			{"reference-x1", func(out [][64]byte, msgs [][][]byte) { sum512MultiReference(out, msgs, 1) }},
			{"reference-x4", sum512x4Reference},
			{"reference-x8", sum512x8Reference},
		}
		for _, implementation := range implementations {
			b.Run(fmt.Sprintf("impl=%s/msg=%d", implementation.name, messageSize), func(b *testing.B) {
				out := make([][64]byte, len(msgs))
				b.ReportAllocs()
				b.SetBytes(bytesPerBatch)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					implementation.fn(out, msgs)
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(msgs)), "ns/msg")
			})
		}
	}
}

// BenchmarkNativeX4 compares the forced AVX2 prototype with four independent
// standard-library hashes. Production dispatch remains scalar regardless of
// these results. Run this on the target with GOMAXPROCS=1 and benchstat.
func BenchmarkNativeX4(b *testing.B) {
	if !nativeX4Available() {
		b.Skip("requires AVX2")
	}
	for _, messageSize := range []int{0, 64, 200, 1232} {
		var storage [nativeX4Width][64 + 1232]byte
		var parts [nativeX4Width][3][]byte
		var msgs [nativeX4Width][][]byte
		var out [nativeX4Width][64]byte
		for lane := range msgs {
			rand.Read(storage[lane][:64+messageSize])
			parts[lane] = [3][]byte{
				storage[lane][:32],
				storage[lane][32:64],
				storage[lane][64 : 64+messageSize],
			}
			msgs[lane] = parts[lane][:]
		}
		for _, implementation := range []struct {
			name string
			fn   func([][64]byte, [][][]byte)
		}{
			{name: "scalar-four", fn: Sum512Batch},
			{name: "native-x4", fn: func(out [][64]byte, msgs [][][]byte) {
				if !sum512x4Native(out, msgs) {
					panic("AVX2 availability changed")
				}
			}},
		} {
			b.Run(fmt.Sprintf("impl=%s/msg=%d", implementation.name, messageSize), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(nativeX4Width * (64 + messageSize)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					implementation.fn(out[:], msgs[:])
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*nativeX4Width), "ns/msg")
			})
		}
		b.Run(fmt.Sprintf("impl=native-x4-fixed3/msg=%d", messageSize), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(nativeX4Width * (64 + messageSize)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !ExperimentalSum512Batch3(out[:], parts[:], nativeX4Width) {
					panic("AVX2 availability changed")
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*nativeX4Width), "ns/msg")
		})
	}
}

// BenchmarkNativeX8 compares the true ZMM x8 kernel against two AVX2 x4
// groups and eight standard-library streams. This is the target-machine
// decision benchmark; Zen 4 executes 512-bit operations over 256-bit
// datapaths, so x8 must earn its added code path empirically.
func BenchmarkNativeX8(b *testing.B) {
	if !nativeX8Available() || !nativeX4Available() {
		b.Skip("requires AVX2 and AVX-512F")
	}
	for _, messageSize := range []int{0, 64, 200, 1232} {
		var storage [nativeX8Width][64 + 1232]byte
		var parts [nativeX8Width][3][]byte
		var msgs [nativeX8Width][][]byte
		var out [nativeX8Width][64]byte
		for lane := range msgs {
			rand.Read(storage[lane][:64+messageSize])
			parts[lane] = [3][]byte{
				storage[lane][:32],
				storage[lane][32:64],
				storage[lane][64 : 64+messageSize],
			}
			msgs[lane] = parts[lane][:]
		}
		for _, implementation := range []struct {
			name string
			fn   func([][64]byte, [][][]byte)
		}{
			{name: "scalar-eight", fn: Sum512Batch},
			{name: "native-two-x4", fn: func(out [][64]byte, msgs [][][]byte) {
				if !ExperimentalSum512Batch(out, msgs, nativeX4Width) {
					panic("AVX2 availability changed")
				}
			}},
			{name: "native-x8", fn: func(out [][64]byte, msgs [][][]byte) {
				if !ExperimentalSum512Batch(out, msgs, nativeX8Width) {
					panic("AVX-512F availability changed")
				}
			}},
		} {
			b.Run(fmt.Sprintf("impl=%s/msg=%d", implementation.name, messageSize), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(nativeX8Width * (64 + messageSize)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					implementation.fn(out[:], msgs[:])
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*nativeX8Width), "ns/msg")
			})
		}
		for _, implementation := range []struct {
			name  string
			width int
		}{
			{name: "native-two-x4-fixed3", width: nativeX4Width},
			{name: "native-x8-fixed3", width: nativeX8Width},
		} {
			b.Run(fmt.Sprintf("impl=%s/msg=%d", implementation.name, messageSize), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(nativeX8Width * (64 + messageSize)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if !ExperimentalSum512Batch3(out[:], parts[:], implementation.width) {
						panic("native fixed3 availability changed")
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*nativeX8Width), "ns/msg")
			})
		}
	}
}

// BenchmarkNativeTails exposes the utilization crossover for naturally
// available batch widths. Every case reuses fixed input descriptors, so any
// reported allocation belongs to the implementation under test.
func BenchmarkNativeTails(b *testing.B) {
	const messageSize = 200
	var storage [17][64 + messageSize]byte
	var parts [17][3][]byte
	var msgs [17][][]byte
	var out [17][64]byte
	for lane := range msgs {
		rand.Read(storage[lane][:])
		parts[lane] = [3][]byte{storage[lane][:32], storage[lane][32:64], storage[lane][64:]}
		msgs[lane] = parts[lane][:]
	}
	for count := 1; count <= len(msgs); count++ {
		implementations := []struct {
			name string
			run  func()
		}{
			{name: "scalar", run: func() { Sum512Batch(out[:count], msgs[:count]) }},
		}
		if nativeX4Available() {
			implementations = append(implementations, struct {
				name string
				run  func()
			}{name: "native-x4", run: func() {
				if !ExperimentalSum512Batch(out[:count], msgs[:count], ExperimentalWidthX4) {
					panic("AVX2 availability changed")
				}
			}})
			implementations = append(implementations, struct {
				name string
				run  func()
			}{name: "native-x4-fixed3", run: func() {
				if !ExperimentalSum512Batch3(out[:count], parts[:count], ExperimentalWidthX4) {
					panic("AVX2 availability changed")
				}
			}})
		}
		if nativeX8Available() {
			implementations = append(implementations, struct {
				name string
				run  func()
			}{name: "native-x8", run: func() {
				if !ExperimentalSum512Batch(out[:count], msgs[:count], ExperimentalWidthX8) {
					panic("AVX-512F availability changed")
				}
			}})
			implementations = append(implementations, struct {
				name string
				run  func()
			}{name: "native-x8-fixed3", run: func() {
				if !ExperimentalSum512Batch3(out[:count], parts[:count], ExperimentalWidthX8) {
					panic("AVX-512F availability changed")
				}
			}})
		}
		for _, implementation := range implementations {
			b.Run(fmt.Sprintf("impl=%s/count=%d", implementation.name, count), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(count * (64 + messageSize)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					implementation.run()
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count), "ns/msg")
			})
		}
	}
}
