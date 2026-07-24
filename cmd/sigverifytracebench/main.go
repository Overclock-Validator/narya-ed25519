// Command sigverifytracebench measures exact Mithril schema-v3 verification
// inputs through stdlib, uncached Narya strict, and Narya's current generic
// Cache. It emits JSON evidence but never promotes the generic-cache result to
// the pending production r51 cache gate.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	narya "github.com/Overclock-Validator/narya/ed25519"
	"github.com/Overclock-Validator/narya/internal/mithriltracev3"
	"github.com/Overclock-Validator/narya/internal/tracebench"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("sigverifytracebench", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inputPath := flags.String("input", "", "Mithril schema-v3 JSONL trace")
	outputPath := flags.String("output", "", "optional JSON evidence output (mode 0600)")
	samples := flags.Int("samples", tracebench.ReleaseSamples, "timing samples per verifier")
	warmups := flags.Int("warmups", 1, "untimed complete-trace passes per verifier")
	minimumTime := flags.Duration("sample-time", tracebench.ReleaseMinimumDuration, "minimum duration of each timing sample")
	minimumRecords := flags.Int("min-records", tracebench.DefaultMinimumRecords, "minimum retained records for diagnostic qualification")
	cacheBytes := flags.Int64("cache-bytes", narya.DefaultMaxTableBytes, "maximum bytes retained by each fresh Cache pass")
	representative := flags.Bool("representative", false, "attest that the trace is a representative real Mithril workload (required for diagnostic qualification)")
	pinnedCore := flags.Bool("pinned-core-attested", false, "attest that this process is externally pinned to one fixed physical core (required for diagnostic qualification)")
	pretty := flags.Bool("pretty", true, "indent JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" {
		if flags.NArg() != 1 {
			return errors.New("sigverifytracebench: provide exactly one trace with -input or as a positional argument")
		}
		*inputPath = flags.Arg(0)
	} else if flags.NArg() != 0 {
		return errors.New("sigverifytracebench: provide exactly one trace with -input or as a positional argument")
	}
	if *outputPath != "" {
		if err := validateOutputPath(*inputPath, *outputPath); err != nil {
			return err
		}
	}
	if err := narya.SetBackend("generic"); err != nil {
		return fmt.Errorf("sigverifytracebench: select backend: %w", err)
	}

	input, err := os.Open(*inputPath)
	if err != nil {
		return fmt.Errorf("sigverifytracebench: open input: %w", err)
	}
	hash := sha256.New()
	trace, parseErr := mithriltracev3.Parse(io.TeeReader(input, hash))
	closeErr := input.Close()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return fmt.Errorf("sigverifytracebench: close input: %w", closeErr)
	}

	priorProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(priorProcs)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	report, err := tracebench.Run(trace, tracebench.Config{
		Samples:                *samples,
		Warmups:                *warmups,
		MinimumSampleDuration:  *minimumTime,
		MinimumRecords:         *minimumRecords,
		CacheBytes:             *cacheBytes,
		RepresentativeAttested: *representative,
		PinnedCoreAttested:     *pinnedCore,
	})
	if err != nil {
		return err
	}
	report.InputSHA256 = hex.EncodeToString(hash.Sum(nil))

	var destination io.Writer = stdout
	var outputFile *os.File
	if *outputPath != "" {
		outputFile, err = os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("sigverifytracebench: open output: %w", err)
		}
		if err := outputFile.Chmod(0o600); err != nil {
			_ = outputFile.Close()
			return fmt.Errorf("sigverifytracebench: protect output: %w", err)
		}
		destination = outputFile
	}
	encoder := json.NewEncoder(destination)
	encoder.SetEscapeHTML(false)
	if *pretty {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(report); err != nil {
		if outputFile != nil {
			_ = outputFile.Close()
		}
		return fmt.Errorf("sigverifytracebench: encode output: %w", err)
	}
	if outputFile != nil {
		if err := outputFile.Close(); err != nil {
			return fmt.Errorf("sigverifytracebench: close output: %w", err)
		}
	}
	return nil
}

func validateOutputPath(inputPath, outputPath string) error {
	inputAbsolute, err := filepath.Abs(inputPath)
	if err != nil {
		return fmt.Errorf("sigverifytracebench: resolve input path: %w", err)
	}
	outputAbsolute, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("sigverifytracebench: resolve output path: %w", err)
	}
	inputInfo, inputErr := os.Stat(inputAbsolute)
	if inputErr != nil {
		return fmt.Errorf("sigverifytracebench: stat input: %w", inputErr)
	}
	outputInfo, outputErr := os.Stat(outputAbsolute)
	if outputErr == nil {
		if os.SameFile(inputInfo, outputInfo) {
			return errors.New("sigverifytracebench: output path resolves to the input trace")
		}
		return errors.New("sigverifytracebench: output path already exists; refusing to overwrite evidence")
	}
	if !errors.Is(outputErr, os.ErrNotExist) {
		return fmt.Errorf("sigverifytracebench: stat output: %w", outputErr)
	}
	if filepath.Clean(inputAbsolute) == filepath.Clean(outputAbsolute) {
		return errors.New("sigverifytracebench: output path resolves to the input trace")
	}
	return nil
}
