package ed25519

import (
	"bufio"
	stdlibed25519 "crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// agaveV4OracleCase is the language-neutral input consumed by the pinned
// Rust oracle in contrib/agave-v4-oracle.  Keeping the verdict in the record
// makes the Rust program compare Agave's actual transaction dependency stack
// with Narya's independently implemented DalekStrict predicate.
type agaveV4OracleCase struct {
	Name             string `json:"name"`
	PublicKeyHex     string `json:"public_key"`
	MessageHex       string `json:"message"`
	SignatureHex     string `json:"signature"`
	NaryaDalekStrict bool   `json:"narya_dalek_strict"`
}

// TestExportAgaveV4OracleCorpus exports the committed Go corpora for the
// standalone Rust differential.  It is inert during ordinary go test runs;
// scripts/check-agave-v4-oracles.sh supplies the output path explicitly.
//
// The exporter deliberately uses the independent generic mathematical oracle,
// not an r51 helper or the production small-order byte table.
func TestExportAgaveV4OracleCorpus(t *testing.T) {
	outputPath := os.Getenv("NARYA_AGAVE_V4_CORPUS_OUT")
	if outputPath == "" {
		t.Skip("set NARYA_AGAVE_V4_CORPUS_OUT to export the Agave v4 oracle corpus")
	}

	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := output.Close(); err != nil {
			t.Errorf("close corpus: %v", err)
		}
	}()
	writer := bufio.NewWriter(output)
	defer func() {
		if err := writer.Flush(); err != nil {
			t.Errorf("flush corpus: %v", err)
		}
	}()
	encoder := json.NewEncoder(writer)

	count := 0
	emit := func(name, publicKeyHex, messageHex, signatureHex string) {
		t.Helper()
		publicKey, err := hex.DecodeString(publicKeyHex)
		if err != nil || len(publicKey) != stdlibed25519.PublicKeySize {
			t.Fatalf("%s: invalid public key", name)
		}
		message, err := hex.DecodeString(messageHex)
		if err != nil {
			t.Fatalf("%s: invalid message", name)
		}
		signature, err := hex.DecodeString(signatureHex)
		if err != nil || len(signature) != stdlibed25519.SignatureSize {
			t.Fatalf("%s: invalid signature", name)
		}
		var publicKeyArray [stdlibed25519.PublicKeySize]byte
		copy(publicKeyArray[:], publicKey)
		item := agaveV4OracleCase{
			Name:             name,
			PublicKeyHex:     publicKeyHex,
			MessageHex:       messageHex,
			SignatureHex:     signatureHex,
			NaryaDalekStrict: referenceVerifyProfile(DalekStrict, &publicKeyArray, message, signature),
		}
		if err := encoder.Encode(&item); err != nil {
			t.Fatalf("%s: encode corpus: %v", name, err)
		}
		count++
	}

	for _, vector := range rfc8032Ed25519Vectors {
		emit("rfc8032/"+vector.name, vector.pub, vector.message, vector.signature)
	}
	for _, vector := range cctvVectors {
		emit(fmt.Sprintf("cctv/%d", vector.tcID), vector.pub, vector.msg, vector.sig)
	}
	for _, vector := range wycheproofVectors {
		emit(fmt.Sprintf("wycheproof/%d", vector.tcID), vector.pub, vector.msg, vector.sig)
	}

	seed := make([]byte, stdlibed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := stdlibed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(stdlibed25519.PublicKey)
	message := []byte("narya agave v4 acceptance boundary")
	validSignature := stdlibed25519.Sign(privateKey, message)
	publicKeyHex := hex.EncodeToString(publicKey)
	messageHex := hex.EncodeToString(message)
	emit("derived/valid", publicKeyHex, messageHex, hex.EncodeToString(validSignature))

	// Exercise every pure-small-order encoding as A and R, then every close
	// one-byte mutation.  The fourteen encodings are derived from the group,
	// independently of both production classifier tables.
	for index, point := range smallOrderEncodingCorpus() {
		pointHex := hex.EncodeToString(point[:])
		emit(fmt.Sprintf("small-order/%02d/as-A", index), pointHex, messageHex, hex.EncodeToString(validSignature))
		asR := append([]byte(nil), validSignature...)
		copy(asR[:32], point[:])
		emit(fmt.Sprintf("small-order/%02d/as-R", index), publicKeyHex, messageHex, hex.EncodeToString(asR))

		for position := 0; position < 32; position++ {
			for _, delta := range []byte{0x01, 0x80} {
				mutated := point
				mutated[position] ^= delta
				mutatedHex := hex.EncodeToString(mutated[:])
				label := fmt.Sprintf("small-order-near/%02d/%02d/%02x", index, position, delta)
				emit(label+"/as-A", mutatedHex, messageHex, hex.EncodeToString(validSignature))
				copy(asR[:32], mutated[:])
				emit(label+"/as-R", publicKeyHex, messageHex, hex.EncodeToString(asR))
			}
		}
	}

	// Every non-canonical low-255-bit field encoding p..p+18, with both sign
	// bits, is included in both point positions.  This is the complete range
	// representable above p in a 255-bit compressed Edwards y-coordinate.
	for offset := 0; offset <= 18; offset++ {
		var encoded [32]byte
		encoded[0] = byte(0xed + offset)
		for index := 1; index < 31; index++ {
			encoded[index] = 0xff
		}
		encoded[31] = 0x7f
		for _, sign := range []byte{0, 0x80} {
			candidate := encoded
			candidate[31] |= sign
			candidateHex := hex.EncodeToString(candidate[:])
			label := fmt.Sprintf("noncanonical-y/p+%02d/sign-%d", offset, sign>>7)
			emit(label+"/as-A", candidateHex, messageHex, hex.EncodeToString(validSignature))
			asR := append([]byte(nil), validSignature...)
			copy(asR[:32], candidate[:])
			emit(label+"/as-R", publicKeyHex, messageHex, hex.EncodeToString(asR))
		}
	}

	// Scalar boundary cases keep a canonical R and vary only S.
	order := [32]byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	orderMinusOne := order
	orderMinusOne[0]--
	orderPlusOne := order
	orderPlusOne[0]++
	scalarCases := []struct {
		name   string
		scalar [32]byte
	}{
		{name: "zero"},
		{name: "L-1", scalar: orderMinusOne},
		{name: "L", scalar: order},
		{name: "L+1", scalar: orderPlusOne},
		{name: "max", scalar: [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, scalarCase := range scalarCases {
		candidate := append([]byte(nil), validSignature...)
		copy(candidate[32:], scalarCase.scalar[:])
		emit("scalar/"+scalarCase.name, publicKeyHex, messageHex, hex.EncodeToString(candidate))
	}

	t.Logf("exported %d Agave v4 oracle cases to %s", count, outputPath)
}
