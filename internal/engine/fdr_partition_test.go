package engine

import (
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func lengthPartitionFDR(matcher *literalMatcher) *fdrMatcher {
	return buildFDR(partitionFDR(fdrLiterals(matcher)))
}

func TestLengthFDRScanMatchesHash(t *testing.T) {
	testFDRScanMatchesHash(t, lengthPartitionFDR)
}

func TestFDRBucketCostMatchesTable(t *testing.T) {
	literals := []fdrLiteral{
		{masks: fdrLiteralMasks([]byte("Abc"), true)},
		{masks: fdrLiteralMasks([]byte("qbf"), false)},
		{masks: fdrLiteralMasks([]byte("aZf"), false)},
	}
	filter := buildFDR([][]fdrLiteral{literals})
	var weights [256]float64
	var total, expected float64
	for value := range weights {
		weights[value] = float64(literalByteWeight(lowerASCII(byte(value))))
		total += weights[value]
	}
	for first := 0; first < 256; first++ {
		for second := 0; second < 256; second++ {
			if filter.table[first|(second&31)<<8]&(1<<16) != 0 {
				continue
			}
			for third := 0; third < 256; third++ {
				if filter.table[second|(third&31)<<8]&(1<<8) == 0 && filter.table[third]&1 == 0 {
					expected += weights[first] * weights[second] * weights[third] / (total * total * total)
				}
			}
		}
	}
	if cost := fdrBucketCost(literals); expected == 0 || math.Abs(cost-expected) > 1e-14 {
		t.Fatalf("cost=%g exhaustive=%g", cost, expected)
	}
}

func TestFDRPartitionPreservesLiterals(t *testing.T) {
	rules, _ := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	literals := fdrLiterals(&db.matcher)
	type identity struct {
		masks  *byteMask
		length int
	}
	counts := make(map[identity]int)
	for _, literal := range literals {
		counts[identity{&literal.masks[0], len(literal.masks)}]++
	}
	groups := optimizeFDRBuckets(partitionFDR(literals))
	if len(groups) > 8 {
		t.Fatal("too many buckets")
	}
	for _, group := range groups {
		for _, literal := range group {
			counts[identity{&literal.masks[0], len(literal.masks)}]--
		}
	}
	for _, count := range counts {
		if count != 0 {
			t.Fatal("literal multiset changed")
		}
	}
}

func fdrCandidateCounts(f *fdrMatcher, data []byte) (int, [8]int) {
	state := f.initial
	var positions int
	var buckets [8]int
	for offset, value := range data {
		key := uint16(value)
		if offset+1 < len(data) {
			key |= uint16(data[offset+1]&31) << 8
		}
		state |= f.table[key]
		candidates := byte(^state)
		if candidates != 0 {
			positions++
		}
		for candidates != 0 {
			bucket := bits.TrailingZeros8(candidates)
			buckets[bucket]++
			candidates &= candidates - 1
		}
		state >>= 8
	}
	return positions, buckets
}

func TestSecretsFDRBuckets(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	optimized := *db
	db.matcher.fdr = lengthPartitionFDR(&db.matcher)
	for bucket, literals := range partitionFDR(fdrLiterals(&db.matcher)) {
		t.Logf("bucket=%d literals=%d min=%d max=%d", bucket, len(literals), len(literals[0].masks), len(literals[len(literals)-1].masks))
	}
	for _, name := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "hyperscan.db", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		positions, counts := fdrCandidateCounts(db.matcher.fdr, data)
		t.Logf("%s: candidates=%d/%d buckets=%v", name, positions, len(data), counts)
		positions, counts = fdrCandidateCounts(optimized.matcher.fdr, data)
		t.Logf("%s: optimized=%d/%d buckets=%v", name, positions, len(data), counts)
		var got, want []Match
		if err := db.Scan(data, nil, func(m Match) error { want = append(want, m); return nil }); err != nil {
			t.Fatal(err)
		}
		if err := optimized.Scan(data, nil, func(m Match) error { got = append(got, m); return nil }); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: different match events", name)
		}
	}
}

func BenchmarkSecretsFDRPartition(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	optimized := db.matcher
	db.matcher.fdr = lengthPartitionFDR(&db.matcher)
	for _, name := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			b.Fatal(err)
		}
		for _, variant := range []struct {
			name string
			scan func([]byte, *Scratch)
		}{
			{"length", db.matcher.scanFDR}, {"probability", optimized.scanFDR},
		} {
			b.Run(filepath.Base(name)+"/"+variant.name, func(b *testing.B) {
				scratch := NewScratch(db)
				if err := scratch.prepare(len(db.patterns)); err != nil {
					b.Fatal(err)
				}
				variant.scan(data, scratch)
				scratch.release()
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					if err := scratch.prepare(len(db.patterns)); err != nil {
						b.Fatal(err)
					}
					variant.scan(data, scratch)
					scratch.release()
				}
			})
		}
	}
}
