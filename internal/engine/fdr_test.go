package engine

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFDRScanMatchesHash(t *testing.T) {
	testFDRScanMatchesHash(t, compileFDR)
}

func testFDRScanMatchesHash(t *testing.T, compile func(*literalMatcher) *fdrMatcher) {
	expressions := []string{`(?i)CaSe-[A-Z0-9]{12}`, `ab[0-9]{2}`, `SensitiveNeedle`, `[0-9]{15}\|[a-z0-9_-]{27}`, `(?i)XYZ`, `(?:abC|dEf)_[0-9]{8}`, `x?token[0-9]{2}`, `(?i)token[0-9]{2}`, `foo\x00bar`, `\x80\xff\x00`, `a+`, `(?m)^hello$`}
	samples := []string{"cAsE-ABCDEFGHIJKL", "ab42", "SensitiveNeedle", "123456789012345|abcdefghijklmnopqrstuvwxyz_", "xYz", "dEf_12345678", "xxtoken42", "TOKEN13", "foo\x00bar", "\x80\xff\x00", "aaaa", "\nhello\n"}
	patterns := make([]*Pattern, len(expressions))
	for i, expression := range expressions {
		patterns[i] = &Pattern{Expression: expression, ID: uint(i), Flags: SomLeftMost}
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	filtered := *db
	filtered.matcher.fdr = compile(&db.matcher)
	if filtered.matcher.fdr == nil {
		t.Fatal("FDR was not compiled")
	}
	scratch, control := NewScratch(&filtered), NewScratch(db)
	check := func(data []byte) {
		t.Helper()
		var got, want []Match
		if err := filtered.Scan(data, scratch, func(match Match) error { got = append(got, match); return nil }); err != nil {
			t.Fatal(err)
		}
		if err := db.Scan(data, control, func(match Match) error { want = append(want, match); return nil }); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Scan(%q): FDR=%v hash=%v", data, got, want)
		}
	}
	check(nil)
	for padding := 0; padding < 32; padding++ {
		for _, sample := range samples {
			for cut := 0; cut <= len(sample); cut++ {
				data := bytes.Repeat([]byte{0xff}, padding)
				data = append(data, sample[:cut]...)
				check(data)
				check(append(data, 0, 0x80, 0xff))
			}
		}
	}
	rng := rand.New(rand.NewSource(41))
	for iteration := 0; iteration < 1000; iteration++ {
		data := make([]byte, rng.Intn(512))
		for i := range data {
			data[i] = byte(rng.Intn(256))
		}
		if len(data) > 0 {
			copy(data[rng.Intn(len(data)):], samples[rng.Intn(len(samples))])
		}
		check(data)
	}
}

func TestSecretsFDRHitsMatchHash(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	suffix := suffixFDR(&db.matcher)
	multiset := func(hits []literalHit) map[literalHit]int {
		result := make(map[literalHit]int)
		for _, hit := range hits {
			hit.next = -1
			result[hit]++
		}
		return result
	}
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml", "hyperscan.db", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		control := NewScratch(db)
		if err := control.prepare(len(db.patterns)); err != nil {
			t.Fatal(err)
		}
		db.matcher.scanHash(data, control)
		control.release()
		want := multiset(control.hits)
		for _, variant := range []struct {
			name string
			scan func([]byte, *Scratch)
		}{{"fdr", db.matcher.scanFDR}, {"stride2", db.matcher.scanFDRStride2}, {"suffix", suffix.scanFDR}} {
			scratch := NewScratch(db)
			if err := scratch.prepare(len(db.patterns)); err != nil {
				t.Fatal(err)
			}
			variant.scan(data, scratch)
			scratch.release()
			if !reflect.DeepEqual(multiset(scratch.hits), want) {
				t.Fatalf("%s/%s: hits=%d hash hits=%d, multisets differ", path, variant.name, len(scratch.hits), len(control.hits))
			}
		}
	}
}

func BenchmarkSecretsFDR(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	filtered := db.matcher
	filtered.fdr = compileFDR(&db.matcher)
	suffix := suffixFDR(&db.matcher)
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			b.Fatal(err)
		}
		for _, variant := range []struct {
			name string
			scan func([]byte, *Scratch)
		}{{"hash", db.matcher.scanHash}, {"fdr", filtered.scanFDR}, {"stride2", filtered.scanFDRStride2}, {"suffix", suffix.scanFDR}} {
			b.Run(filepath.Base(path)+"/"+variant.name, func(b *testing.B) {
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

func suffixFDR(matcher *literalMatcher) literalMatcher {
	groups := make([][]trigger, len(matcher.hashed.groups))
	for i, group := range matcher.hashed.groups {
		groups[i] = matcher.hashed.triggers[group.start:group.end]
	}
	result := literalMatcher{hashed: compileLiteralSuffixGroups(groups), hashPairs: matcher.hashPairs}
	result.fdr = compileFDR(&result)
	return result
}
