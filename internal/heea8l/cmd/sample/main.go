// Command sample runs the non-production HEEA width experiment.
//
// Usage:
//
//	go run ./internal/heea8l/cmd/sample -samples 1000000
//
// Each sample index is mapped independently to a uniformly distributed
// challenge in [0,L) with SHA-512 and rejection sampling. Counts therefore do
// not depend on worker count. Timings are measurements of the current machine,
// while counts and histograms are reproducible.
package main

import (
	"crypto/sha512"
	"encoding/binary"
	"flag"
	"fmt"
	"math/big"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/Overclock-Validator/narya/internal/heea8l"
)

type stats struct {
	samples      uint64
	draws        uint64
	selectorTime time.Duration // cumulative worker wall time around Select
	fallback128  uint64
	fallback132  uint64
	fallback136  uint64
	invalid      uint64
	widthSum     uint64
	widths       map[int]uint64
}

func main() {
	sampleCount := flag.Uint64("samples", 1_000_000, "number of deterministic uniform challenges")
	workers := flag.Int("workers", runtime.GOMAXPROCS(0), "parallel selector workers")
	flag.Parse()
	if *sampleCount == 0 {
		panic("samples must be nonzero")
	}
	if *workers <= 0 {
		panic("workers must be positive")
	}
	if uint64(*workers) > *sampleCount {
		*workers = int(*sampleCount)
	}

	order := heea8l.Order()
	cutoff := rejectionCutoff(order)
	started := time.Now()
	results := make(chan stats, *workers)
	var wg sync.WaitGroup
	chunk := (*sampleCount + uint64(*workers) - 1) / uint64(*workers)
	for worker := 0; worker < *workers; worker++ {
		first := uint64(worker) * chunk
		last := first + chunk
		if last > *sampleCount {
			last = *sampleCount
		}
		if first >= last {
			continue
		}
		wg.Add(1)
		go func(first, last uint64) {
			defer wg.Done()
			results <- runRange(first, last, order, cutoff)
		}(first, last)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	total := stats{widths: make(map[int]uint64)}
	for local := range results {
		total.samples += local.samples
		total.draws += local.draws
		total.selectorTime += local.selectorTime
		total.fallback128 += local.fallback128
		total.fallback132 += local.fallback132
		total.fallback136 += local.fallback136
		total.invalid += local.invalid
		total.widthSum += local.widthSum
		for width, count := range local.widths {
			total.widths[width] += count
		}
	}
	elapsed := time.Since(started)

	fmt.Printf("HEEA modulo-8L deterministic experiment\n")
	fmt.Printf("samples=%d workers=%d domain=heea8l-sample-v1\n", total.samples, *workers)
	fmt.Printf("wall=%s throughput=%.0f samples/s end_to_end=%.0f ns/sample\n",
		elapsed.Round(time.Millisecond), float64(total.samples)/elapsed.Seconds(), float64(elapsed.Nanoseconds())/float64(total.samples))
	fmt.Printf("selector_worker_time=%s selector_under_load=%.0f ns/sample draws/sample=%.6f invalid=%d\n",
		total.selectorTime.Round(time.Millisecond), float64(total.selectorTime.Nanoseconds())/float64(total.samples),
		float64(total.draws)/float64(total.samples), total.invalid)
	fmt.Printf("candidate_width_mean=%.6f bits\n", float64(total.widthSum)/float64(total.samples-total.invalid))

	printGate(128, total.samples, total.fallback128, 88.8533)
	printGate(132, total.samples, total.fallback132, 99.9595)
	printGate(136, total.samples, total.fallback136, 99.9997)

	keys := make([]int, 0, len(total.widths))
	for width := range total.widths {
		keys = append(keys, width)
	}
	sort.Ints(keys)
	fmt.Println("candidate_width_histogram:")
	for _, width := range keys {
		fmt.Printf("  %3d bits: %d\n", width, total.widths[width])
	}

	printPathological()
}

func runRange(first, last uint64, order, cutoff *big.Int) stats {
	local := stats{widths: make(map[int]uint64)}
	for index := first; index < last; index++ {
		k, draws := uniformChallenge(index, order, cutoff)
		local.draws += draws
		started := time.Now()
		selection := heea8l.Select(k, heea8l.Width136)
		local.selectorTime += time.Since(started)
		local.samples++
		if selection.Fallback == heea8l.FallbackInvalidChallenge || selection.Fallback == heea8l.FallbackInvalidWidth {
			local.invalid++
			continue
		}
		width := selection.Candidate.BitLen()
		local.widths[width]++
		local.widthSum += uint64(width)
		if width > 128 {
			local.fallback128++
		}
		if width > 132 {
			local.fallback132++
		}
		if width > 136 {
			local.fallback136++
		}
	}
	return local
}

func rejectionCutoff(order *big.Int) *big.Int {
	space := new(big.Int).Lsh(big.NewInt(1), 256)
	whole := new(big.Int).Quo(space, order)
	return whole.Mul(whole, order)
}

func uniformChallenge(index uint64, order, cutoff *big.Int) (*big.Int, uint64) {
	var input [32]byte
	copy(input[:16], "heea8l-sample-v1")
	binary.LittleEndian.PutUint64(input[16:24], index)
	for attempt := uint64(0); ; attempt++ {
		binary.LittleEndian.PutUint64(input[24:32], attempt)
		digest := sha512.Sum512(input[:])
		x := new(big.Int).SetBytes(digest[:32])
		if x.Cmp(cutoff) < 0 {
			return x.Mod(x, order), attempt + 1
		}
	}
}

func printGate(width int, samples, fallbacks uint64, referenceCoverage float64) {
	coverage := 100 * float64(samples-fallbacks) / float64(samples)
	fmt.Printf("W=%d admitted=%d fallback=%d coverage=%.6f%% reference=%.4f%% delta=%+.6fpp\n",
		width, samples-fallbacks, fallbacks, coverage, referenceCoverage, coverage-referenceCoverage)
}

func printPathological() {
	n := heea8l.Modulus()
	k := new(big.Int).Sub(n, big.NewInt(2))
	k.Quo(k, big.NewInt(10))
	selection := heea8l.Select(k, heea8l.Width136)
	fmt.Printf("pathological k=(N-2)/10 candidate_width=%d use=%v fallback=%v rho=%s tau=%s\n",
		selection.Candidate.BitLen(), selection.UseCandidate, selection.Fallback,
		&selection.Candidate.Rho, &selection.Candidate.Tau)
}
