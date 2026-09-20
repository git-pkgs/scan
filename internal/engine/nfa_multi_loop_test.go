package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNFAMultipleLoopScan(t *testing.T) {
	expressions := []string{
		`^key(?:[^x]*x|[^y]*y)$`,
		`key(?:[^x]*x|[^y]*y)\b`,
		`^key(?:.*|.*(?:[\r\n]{1,2}.*){1,5}) done$`,
		`^key(?:a*\b|a*!)$`,
		`(?:key|e)y?(?:[^x]*x|[^y]*y)`,
	}
	for _, expression := range expressions {
		db, err := Compile(&Pattern{Expression: expression, Flags: SomLeftMost | AllowEmpty})
		if err != nil {
			t.Fatal(err)
		}
		loaded, _ := roundTripDatabase(t, db)
		for _, candidate := range []*Database{db, loaded} {
			candidate.patterns[0].dfa = nil
			control := withoutNFALoops(candidate)
			for value := 0; value < 256; value++ {
				for _, ending := range []string{"", "x", "y", "x!", "\n done", " done"} {
					input := append(append([]byte("key"), bytes.Repeat([]byte{byte(value)}, 64)...), ending...)
					compareLoadedScan(t, control, candidate, input)
				}
			}
		}
	}
}

func TestNFAMultipleLoopsSkipClosures(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `^key(?:[^x]*x|[^y]*y)$`, Flags: SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	loaded, _ := roundTripDatabase(t, db)
	for _, candidate := range []*Database{db, loaded} {
		candidate.patterns[0].dfa = nil
		control := withoutNFALoops(candidate)
		for _, ending := range []string{"", "x", "y", "xy", "z"} {
			input := append(append([]byte("key"), bytes.Repeat([]byte{'!'}, 4096)...), ending...)
			fast, slow := NewScratch(candidate), NewScratch(control)
			var got, want []Match
			if err := candidate.Scan(input, fast, func(m Match) error { got = append(got, m); return nil }); err != nil {
				t.Fatal(err)
			}
			if err := control.Scan(input, slow, func(m Match) error { want = append(want, m); return nil }); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("ending %q: fast=%v slow=%v", ending, got, want)
			}
			if slow.nfa.generation < 4096 || fast.nfa.generation >= 64 {
				t.Fatalf("ending %q: closures fast=%d slow=%d", ending, fast.nfa.generation, slow.nfa.generation)
			}
		}
	}
}

func BenchmarkSecretsMultiLoops(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	files := []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "hyperscan.db", "secrets"}
	for i := range files {
		files[i] = filepath.Join(root, files[i])
	}
	if path := os.Getenv("SCAN_DIAGNOSTIC_BLOB"); path != "" {
		files = append(files, path)
	}
	for _, path := range files {
		input, err := os.ReadFile(path)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(filepath.Base(path), func(b *testing.B) {
			scratch := NewScratch(db)
			handler := func(Match) error { return nil }
			if err := db.Scan(input, scratch, handler); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				if err := db.Scan(input, scratch, handler); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
