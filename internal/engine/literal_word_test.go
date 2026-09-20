package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

func TestFoldASCIIWordAllAdjacentBytes(t *testing.T) {
	for lane := 0; lane < 8; lane++ {
		shift := lane * 8
		nextShift := ((lane + 1) % 8) * 8
		for pair := 0; pair < 1<<16; pair++ {
			word := uint64(0x7fff00415a4080ff)
			word &^= uint64(255)<<shift | uint64(255)<<nextShift
			word |= uint64(pair&255)<<shift | uint64(pair>>8)<<nextShift
			var want uint64
			for position := 0; position < 8; position++ {
				value := byte(word >> (position * 8))
				if value >= 'A' && value <= 'Z' {
					value += 'a' - 'A'
				}
				want |= uint64(value) << (position * 8)
			}
			if got := foldASCIIWord(word); got != want {
				t.Fatalf("fold(%016x) = %016x, want %016x", word, got, want)
			}
		}
	}
}

func TestScanAcrossWordBoundaries(t *testing.T) {
	expressions := []string{`(?i)CaSe-[A-Z0-9]{12}`, `ab[0-9]{2}`, `SensitiveNeedle`, `[0-9]{15}\|[a-z0-9_-]{27}`, `(?i)XYZ`, `(?:abC|dEf)_[0-9]{8}`}
	samples := []string{"cAsE-ABCDEFGHIJKL", "ab42", "SensitiveNeedle", "123456789012345|abcdefghijklmnopqrstuvwxyz_", "xYz", "dEf_12345678"}
	patterns := make([]*Pattern, len(expressions))
	references := make([]*regexp.Regexp, len(expressions))
	for i, expression := range expressions {
		patterns[i] = &Pattern{Expression: expression, ID: uint(i), Flags: SingleMatch | SomLeftMost}
		references[i] = regexp.MustCompile(expression)
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	scratch := NewScratch(db)
	for padding := 0; padding < 32; padding++ {
		for _, sample := range samples {
			for cut := 0; cut <= len(sample); cut++ {
				data := bytes.Repeat([]byte{0xff}, padding)
				data = append(data, sample[:cut]...)
				data = append(data, 0, 0x80, 0xff)
				got := make(map[uint]Match)
				if err := db.Scan(data, scratch, func(m Match) error {
					got[m.ID] = m
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				for id, reference := range references {
					want := reference.FindIndex(data)
					match, exists := got[uint(id)]
					if exists != (want != nil) || exists && (match.From != uint64(want[0]) || match.To != uint64(want[1])) {
						t.Fatalf("Scan(%q), pattern %s: got %v (%v), want %v", data, expressions[id], match, exists, want)
					}
				}
			}
		}
	}
}

func TestScanSharedLiteralsKeepPatternBounds(t *testing.T) {
	expressions := []string{`token[0-9]{2}`, `x?token[0-9]{2}`, `(?i)token[0-9]{2}`, `token[0-9]{2}`}
	patterns := make([]*Pattern, len(expressions))
	for i, expression := range expressions {
		patterns[i] = &Pattern{Expression: expression, ID: uint(i), Flags: SingleMatch | SomLeftMost}
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.matcher.hashed.groups) >= len(db.matcher.hashed.triggers) {
		t.Fatal("no shared literal groups")
	}
	scratch := NewScratch(db)
	for padding := 0; padding < 16; padding++ {
		data := append(bytes.Repeat([]byte{0xff}, padding), []byte("TOKEN13 xxtoken42")...)
		got := make(map[uint]Match)
		if err := db.Scan(data, scratch, func(m Match) error {
			got[m.ID] = m
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for id, expression := range expressions {
			want := regexp.MustCompile(expression).FindIndex(data)
			match, exists := got[uint(id)]
			if !exists || match.From != uint64(want[0]) || match.To != uint64(want[1]) {
				t.Fatalf("Scan(%q), pattern %s: got %v (%v), want %v", data, expression, match, exists, want)
			}
		}
	}
}

func BenchmarkSecretsLiteralDispatch(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	groups := make([][]trigger, len(db.matcher.hashed.triggers))
	for i, candidate := range db.matcher.hashed.triggers {
		groups[i] = []trigger{candidate}
	}
	ungrouped := literalMatcher{hashed: compileLiteralHashGroups(groups, nil), hashPairs: db.matcher.hashPairs}
	sharedGroups := make([][]trigger, len(db.matcher.hashed.groups))
	for i, group := range db.matcher.hashed.groups {
		sharedGroups[i] = db.matcher.hashed.triggers[group.start:group.end]
	}
	baseline := literalMatcher{hashed: compileLiteralHashGroups(sharedGroups, nil), hashPairs: db.matcher.hashPairs}
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			b.Fatal(err)
		}
		for _, variant := range []struct {
			name string
			scan func([]byte, *Scratch)
		}{{"scalar", ungrouped.scanHashScalar}, {"word", ungrouped.scanHashUngrouped}, {"grouped", baseline.scanHashGrouped}, {"weighted", db.matcher.scanHashGrouped}, {"checked", db.matcher.scanHashChecked}, {"bucket", db.matcher.scanHash}, {"combined", db.matcher.scanHashCombined}} {
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

func TestLiteralDispatchVariantsAgree(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	groups := make([][]trigger, len(db.matcher.hashed.triggers))
	for i, candidate := range db.matcher.hashed.triggers {
		groups[i] = []trigger{candidate}
	}
	ungrouped := literalMatcher{hashed: compileLiteralHashGroups(groups, nil), hashPairs: db.matcher.hashPairs}
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		var want map[literalHit]int
		for _, variant := range []struct {
			name string
			scan func([]byte, *Scratch)
		}{{"scalar", ungrouped.scanHashScalar}, {"word", ungrouped.scanHashUngrouped}, {"grouped", db.matcher.scanHash}, {"checked", db.matcher.scanHashChecked}, {"combined", db.matcher.scanHashCombined}} {
			scratch := NewScratch(db)
			if err := scratch.prepare(len(db.patterns)); err != nil {
				t.Fatal(err)
			}
			variant.scan(data, scratch)
			scratch.release()
			got := make(map[literalHit]int)
			for _, hit := range scratch.hits {
				hit.next = -1
				got[hit]++
			}
			if want == nil {
				want = got
			} else if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s/%s: %d distinct hits differ from %d scalar hits", path, variant.name, len(got), len(want))
			}
		}
	}
}
