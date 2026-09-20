package engine

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStartClosureScanMatchesNFA(t *testing.T) {
	expressions := []string{`a+b`, `(?:a?)*b`, `(?m)^a?$`, `\ba*\b`, `\Ba+\B`, `(?:\b|a)b`, `(?:ab|a)c`, `(?:a|b)*c`, `key.{0,4}ab+c`, `é.?界`, `(?:^|\n)(?:ab|c)?$`}
	for _, flags := range []Flags{0, UTF8} {
		patterns := make([]*Pattern, len(expressions))
		for i, expression := range expressions {
			patterns[i] = &Pattern{Expression: expression, ID: uint(i), Flags: flags | AllowEmpty | SomLeftMost}
		}
		db, err := Compile(patterns...)
		if err != nil {
			t.Fatal(err)
		}
		for i := range db.patterns {
			db.patterns[i].dfa = nil
		}
		baseline := *db
		baseline.patterns = append([]compiledPattern(nil), db.patterns...)
		for i := range baseline.patterns {
			baseline.patterns[i].startClosures = nil
		}
		scratch, control := NewScratch(db), NewScratch(&baseline)
		rng := rand.New(rand.NewSource(31))
		alphabet := []rune("aaabckey \né界_!")
		for iteration := 0; iteration < 1000; iteration++ {
			runes := make([]rune, rng.Intn(64))
			for i := range runes {
				runes[i] = alphabet[rng.Intn(len(alphabet))]
			}
			data := []byte(string(runes))
			if iteration < 3 {
				data = append(bytes.Repeat([]byte{'!'}, maxPrecomputedClosureInput+iteration), data...)
			}
			if iteration%10 == 0 {
				scratch.nfa.generation = ^uint32(0)
				control.nfa.generation = ^uint32(0)
			}
			var got, want []Match
			if err := db.Scan(data, scratch, func(m Match) error { got = append(got, m); return nil }); err != nil {
				t.Fatal(err)
			}
			if err := baseline.Scan(data, control, func(m Match) error { want = append(want, m); return nil }); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("flags=%v iteration=%d input length=%d: cached=%v dynamic=%v", flags, iteration, len(data), got, want)
			}
		}
	}
}

func BenchmarkSecretsStartClosures(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	baseline := *db
	baseline.patterns = append([]compiledPattern(nil), db.patterns...)
	for i := range baseline.patterns {
		baseline.patterns[i].startClosures = nil
	}
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml", "hyperscan.db", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			b.Fatal(err)
		}
		for _, variant := range []struct {
			name string
			db   *Database
		}{{"walk", &baseline}, {"cached", db}} {
			b.Run(filepath.Base(path)+"/"+variant.name, func(b *testing.B) {
				scratch := NewScratch(variant.db)
				handler := func(Match) error { return nil }
				if err := variant.db.Scan(data, scratch, handler); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					if err := variant.db.Scan(data, scratch, handler); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
