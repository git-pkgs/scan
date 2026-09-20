package engine

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func withoutNFALoops(db *Database) *Database {
	control := *db
	control.patterns = append([]compiledPattern(nil), db.patterns...)
	for i := range control.patterns {
		control.patterns[i].loops = nil
	}
	return &control
}

func TestNFALoopSkipsClosuresAfterLoad(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `^key[^x]*x$`, Flags: SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	loaded, _ := roundTripDatabase(t, db)
	for _, accelerated := range []*Database{db, loaded} {
		accelerated.patterns[0].dfa = nil
		control := withoutNFALoops(accelerated)
		for _, suffix := range []string{"x", ""} {
			data := append(append([]byte("key"), bytes.Repeat([]byte{'!'}, 4096)...), suffix...)
			fast, slow := NewScratch(accelerated), NewScratch(control)
			var got, want []Match
			if err := accelerated.Scan(data, fast, func(m Match) error { got = append(got, m); return nil }); err != nil {
				t.Fatal(err)
			}
			if err := control.Scan(data, slow, func(m Match) error { want = append(want, m); return nil }); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) || (len(got) == 1) != (suffix == "x") {
				t.Fatalf("suffix=%q: got=%v want=%v", suffix, got, want)
			}
			if slow.nfa.generation < 4096 || fast.nfa.generation >= slow.nfa.generation/2 {
				t.Fatalf("closures not skipped: accelerated=%d control=%d", fast.nfa.generation, slow.nfa.generation)
			}
		}
	}
}

func TestNFALoopScanMatchesControl(t *testing.T) {
	expressions := []string{`\{[^{]+needle[^}]+\}`, `key[^\n]*end`, `\{[^{]+(?:alpha|bravo)[^}]*\}`, `a+\bb`, `a*`, `^ab.*cd$`, `(?:ab|a)*end`, `(?s)key.*end`, `(?m)key[^\n]*$`, `x[^x]+é`, `\{[^{]+needle\b`, `(?:ab?)*z`}
	for _, flags := range []Flags{SomLeftMost | AllowEmpty, Caseless | SomLeftMost | AllowEmpty, SingleMatch | SomLeftMost | AllowEmpty, UTF8 | SomLeftMost | AllowEmpty} {
		patterns := make([]*Pattern, len(expressions))
		for i, expression := range expressions {
			patterns[i] = &Pattern{Expression: expression, ID: uint(i), Flags: flags}
		}
		db, err := Compile(patterns...)
		if err != nil {
			t.Fatal(err)
		}
		loops := 0
		for i := range db.patterns {
			db.patterns[i].dfa = nil
			for _, table := range db.patterns[i].loops {
				if table != nil {
					loops++
				}
			}
		}
		if !flags.has(UTF8) && loops == 0 {
			t.Fatal("no loops compiled")
		}
		control := withoutNFALoops(db)
		fastScratch, slowScratch := NewScratch(db), NewScratch(control)
		rng := rand.New(rand.NewSource(83))
		inputs := [][]byte{
			nil, []byte("keyend"), []byte("{.needle x} {xneedle_y}"), []byte("key\nend"),
			append(append([]byte("{x"), bytes.Repeat([]byte{'!'}, maxPrecomputedClosureInput+1)...), []byte("needle x}")...),
			append([]byte("key"), bytes.Repeat([]byte{0}, 4096)...),
		}
		for value := 0; value < 256; value++ {
			inputs = append(inputs, append(append([]byte("{x"), bytes.Repeat([]byte{byte(value)}, 64)...), []byte("needle x}")...))
		}
		alphabet := []byte("{aabxy}keyend lphrvz\n\x00\xffé")
		for i := 0; i < 1000; i++ {
			input := make([]byte, rng.Intn(192))
			for j := range input {
				input[j] = alphabet[rng.Intn(len(alphabet))]
			}
			inputs = append(inputs, input)
		}
		for i, input := range inputs {
			if i%17 == 0 {
				fastScratch.nfa.generation, slowScratch.nfa.generation = ^uint32(0), ^uint32(0)
			}
			var got, want []Match
			if err := db.Scan(input, fastScratch, func(m Match) error { got = append(got, m); return nil }); err != nil {
				t.Fatal(err)
			}
			if err := control.Scan(input, slowScratch, func(m Match) error { want = append(want, m); return nil }); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("flags=%v input=%d length=%d: accelerated=%v control=%v", flags, i, len(input), got, want)
			}
		}
	}
}

func TestSecretsNFALoops(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	control := withoutNFALoops(db)
	for i, p := range db.patterns {
		if rules[i].id != "gcp-service-account" && rules[i].id != "gcp-application-default-credentials" {
			continue
		}
		count := 0
		for _, table := range p.loops {
			if table != nil {
				count++
			}
		}
		t.Logf("%s: %d self-loop states", rules[i].id, count)
		if count == 0 {
			t.Fatal("missing GCP loops")
		}
	}
	for _, name := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml", "hyperscan.db", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		compareLoadedScan(t, control, db, data)
	}
}

func BenchmarkSecretsNFALoops(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	control := withoutNFALoops(db)
	for _, name := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml", "hyperscan.db", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			b.Fatal(err)
		}
		for _, variant := range []struct {
			name string
			db   *Database
		}{{"control", control}, {"loops", db}} {
			b.Run(filepath.Base(name)+"/"+variant.name, func(b *testing.B) {
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
