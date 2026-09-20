package engine

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func longerFragmentFDR(matcher *literalMatcher, power int) literalMatcher {
	groups := make([][]trigger, len(matcher.hashed.groups))
	costs := make(map[uint32]int)
	for i, group := range matcher.hashed.groups {
		groups[i] = matcher.hashed.triggers[group.start:group.end]
		seen := make(map[uint32]bool)
		var window uint32
		for offset, value := range group.text {
			window = window<<8&0xffffff | uint32(lowerASCII(value))
			if offset >= 2 && !seen[window] {
				costs[window]++
				seen[window] = true
			}
		}
	}
	for fragment, frequency := range costs {
		costs[fragment] = frequency * frequency
	}
	choose := func(text []byte) (uint32, int) {
		var best, fragment uint32
		bestEnd, bestScore := 2, math.Inf(1)
		for offset, value := range text {
			fragment = fragment<<8&0xffffff | uint32(lowerASCII(value))
			if offset < 2 {
				continue
			}
			score := float64(literalByteWeight(byte(fragment>>16)) * literalByteWeight(byte(fragment>>8)) * literalByteWeight(byte(fragment)) * max(1, costs[fragment]))
			for p := 0; p < power; p++ {
				score /= float64(min(offset+1, 8))
			}
			if score < bestScore {
				best, bestEnd, bestScore = fragment, offset, score
			}
		}
		return best, bestEnd
	}
	result := literalMatcher{hashed: compileLiteralChosenGroups(groups, choose), hashPairs: matcher.hashPairs}
	result.fdr = compileFDR(&result)
	return result
}

func TestFDRFragmentSelectionThreshold(t *testing.T) {
	for _, count := range []int{1, 63, 64} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			patterns := []*Pattern{{Expression: `abcXYZ`, ID: 0}}
			for id := 1; id < count; id++ {
				patterns = append(patterns, &Pattern{Expression: fmt.Sprintf(`needle%04d`, id), ID: uint(id)})
			}
			db, err := Compile(patterns...)
			if err != nil {
				t.Fatal(err)
			}
			wantEnd := 3
			if count >= 64 {
				wantEnd = 5
			}
			if (db.matcher.fdr != nil) != (count >= 64) {
				t.Fatal("unexpected FDR selection")
			}
			if got := db.matcher.hashed.groups[0].pairEnd; got != wantEnd {
				t.Fatalf("fragment end = %d, want %d", got, wantEnd)
			}
			var matches []Match
			if err := db.Scan([]byte("token=abcXYZ"), NewScratch(db), func(match Match) error {
				matches = append(matches, match)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(matches, []Match{{ID: 0, To: 12}}) {
				t.Fatalf("unexpected matches: %v", matches)
			}
		})
	}
}

func TestLongerFDRFragments(t *testing.T) {
	patterns := []*Pattern{
		{Expression: `(?i)prefixToken-[0-9]{4}`, ID: 1, Flags: SomLeftMost},
		{Expression: `x?prefixToken-[a-z]{4}`, ID: 2, Flags: SomLeftMost},
		{Expression: `SensitiveNeedle`, ID: 3, Flags: SomLeftMost},
		{Expression: `\x80\xffprefix\x00`, ID: 4, Flags: SomLeftMost},
		{Expression: `(?i)XYZ`, ID: 5, Flags: SomLeftMost},
		{Expression: `ab[0-9]{2}`, ID: 6, Flags: SomLeftMost},
		{Expression: `a*`, ID: 7, Flags: SomLeftMost | AllowEmpty},
	}
	for id := 0; id < 80; id++ {
		patterns = append(patterns, &Pattern{
			Expression: fmt.Sprintf(`(?i)fragment-%04d-sequence-[a-z0-9]{4}`, id),
			ID:         uint(id + 8),
			Flags:      SomLeftMost,
		})
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	if db.matcher.fdr == nil {
		t.Fatal("FDR was not compiled")
	}
	control := *db
	control.matcher.fdr = nil
	samples := []string{"PrEfIxToKeN-1234", "xprefixToken-abcd", "SensitiveNeedle", "\x80\xffprefix\x00", "xYz", "ab42", "FRAGMENT-0000-sequence-A1B2", "fragment-0039-SEQUENCE-9AbC", "fragment-0079-sequence-0123"}
	for power := 1; power <= 3; power++ {
		candidate := *db
		candidate.matcher = longerFragmentFDR(&db.matcher, power)
		loaded, _ := roundTripDatabase(t, &candidate)
		for padding := 0; padding < 32; padding++ {
			for _, sample := range samples {
				for cut := 0; cut <= len(sample); cut++ {
					input := append(bytes.Repeat([]byte{0xff}, padding), sample[:cut]...)
					compareLoadedScan(t, &control, &candidate, input)
					compareLoadedScan(t, &control, loaded, append(input, 0, 0x80, 0xff))
				}
			}
		}
		rng := rand.New(rand.NewSource(97))
		for trial := 0; trial < 1000; trial++ {
			input := make([]byte, rng.Intn(512))
			_, _ = rng.Read(input)
			if len(input) > 0 {
				copy(input[rng.Intn(len(input)):], samples[rng.Intn(len(samples))])
			}
			compareLoadedScan(t, &control, &candidate, input)
			compareLoadedScan(t, &control, loaded, input)
		}
	}
}

func TestSecretsLongerFDRFragments(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	want := longerFragmentFDR(&db.matcher, 1)
	if !reflect.DeepEqual(db.matcher, want) {
		t.Fatal("compiled fragment selection differs from the prefix-weighted reference")
	}
	for power := 0; power <= 3; power++ {
		candidate := *db
		candidate.matcher = longerFragmentFDR(&db.matcher, power)
		var lengths [9]int
		for _, group := range candidate.matcher.hashed.groups {
			lengths[min(group.pairEnd+1, 8)]++
		}
		t.Logf("power=%d lengths=%v", power, lengths)
		for _, name := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml", "betterleaks/testdata/repos/nogit/api.go", "betterleaks/testdata/repos/nogit/.env.prod", "hyperscan.db", "secrets"} {
			data, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			compareLoadedScan(t, db, &candidate, data)
			positions, _ := fdrCandidateCounts(candidate.matcher.fdr, data)
			t.Logf("power=%d %s candidates=%d", power, name, positions)
		}
	}
}

func BenchmarkSecretsFDRFragments(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	var variants []*Database
	for power := 0; power <= 3; power++ {
		candidate := *db
		candidate.matcher = longerFragmentFDR(&db.matcher, power)
		variants = append(variants, &candidate)
	}
	for _, name := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			b.Fatal(err)
		}
		for power, candidate := range variants {
			b.Run(fmt.Sprintf("%s/power%d", filepath.Base(name), power), func(b *testing.B) {
				scratch := NewScratch(candidate)
				handler := func(Match) error { return nil }
				if err := candidate.Scan(data, scratch, handler); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					if err := candidate.Scan(data, scratch, handler); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
