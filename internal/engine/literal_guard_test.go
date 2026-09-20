package engine

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiteralGuardPublicScan(t *testing.T) {
	tail := strings.Repeat(`[ab]x`, maxDFAProgram/2+1)
	expression := `\bkey\b[^\n]*(?:\n[^\n]*){0,2}[ \t]--token ` + tail
	db, err := Compile(&Pattern{Expression: expression, Flags: SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	if db.patterns[0].literalGuard == nil || db.patterns[0].literalGuard.newlines != 2 {
		t.Fatal("missing bounded-newline guard")
	}
	loaded, _ := roundTripDatabase(t, db)
	control := *db
	control.patterns = append([]compiledPattern(nil), db.patterns...)
	control.patterns[0].literalGuard = nil
	suffix := []byte(strings.Repeat("ax", maxDFAProgram/2+1))
	for _, candidate := range []*Database{db, loaded} {
		for lines := 0; lines <= 3; lines++ {
			for _, width := range []int{0, 15, maxLiteralGuardBytes - 10, maxLiteralGuardBytes, maxLiteralGuardBytes + 1} {
				input := []byte("key" + strings.Repeat("\n", lines) + strings.Repeat("!", width) + " --token ")
				input = append(input, suffix...)
				compareLoadedScan(t, &control, candidate, input)
				matched, err := candidate.Match(input, nil)
				if err != nil || matched != (lines <= 2) {
					t.Fatalf("lines=%d width=%d Match=%v error=%v", lines, width, matched, err)
				}
			}
		}
		for value := 0; value < 256; value++ {
			input := append([]byte("key!!!"), byte(value))
			input = append(input, []byte("--token ")...)
			input = append(input, suffix...)
			compareLoadedScan(t, &control, candidate, input)
			for _, length := range []int{0, 3, 8, len(input) - 1} {
				compareLoadedScan(t, &control, candidate, input[:length])
			}
		}
		input := append([]byte("key"), bytes.Repeat([]byte(" words\n"), 20)...)
		input = append(input, []byte(" --token ")...)
		input = append(input, suffix...)
		fast, slow := NewScratch(candidate), NewScratch(&control)
		if _, err := candidate.Match(input, fast); err != nil {
			t.Fatal(err)
		}
		if _, err := control.Match(input, slow); err != nil {
			t.Fatal(err)
		}
		if fast.nfa.generation != 0 || slow.nfa.generation == 0 {
			t.Fatalf("guard failed to skip NFA: fast=%d slow=%d", fast.nfa.generation, slow.nfa.generation)
		}
	}
}

func TestLiteralGuardRejectsInvalidTables(t *testing.T) {
	for _, guard := range []*literalGuard{
		{literals: [][]byte{[]byte("flag")}, newlines: -1},
		{literals: [][]byte{[]byte("flag")}, newlines: maxLiteralGuardNewlines + 1},
		{literals: [][]byte{nil}},
		{literals: [][]byte{[]byte("a")}},
		{literals: [][]byte{bytes.Repeat([]byte{'a'}, maxLiteralGuardBytes+1)}},
		{},
	} {
		db, err := Compile(&Pattern{Expression: "needle"})
		if err != nil {
			t.Fatal(err)
		}
		db.patterns[0].literalGuard = guard
		encoded, err := db.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalDatabase(encoded); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted invalid guard: %+v error=%v", guard, err)
		}
	}
}

func literalGuardExperiment(tb testing.TB) (*Database, *Database, string) {
	tb.Helper()
	rules, root := loadSecretsRules(tb)
	db := compileSecretsRules(tb, rules)
	control := *db
	control.patterns = append([]compiledPattern(nil), db.patterns...)
	for i, rule := range rules {
		if guard := db.patterns[i].literalGuard; guard != nil {
			tb.Logf("%s: literal guard=%+v", rule.id, guard)
		}
		control.patterns[i].literalGuard = nil
	}
	triggers := append(append([]trigger(nil), db.matcher.hashed.triggers...), db.matcher.hashPairs.triggers...)
	db.size = estimateSize(db, triggers)
	return db, &control, root
}

func TestSecretsLiteralGuard(t *testing.T) {
	db, control, root := literalGuardExperiment(t)
	loaded, _ := roundTripDatabase(t, db)
	files := []string{filepath.Join(root, "main.go"), filepath.Join(root, "betterleaks/config/betterleaks.toml"), filepath.Join(root, "secrets")}
	if directory := os.Getenv("SCAN_DIAGNOSTIC_DIR"); directory != "" {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			files = append(files, filepath.Join(directory, entry.Name()))
		}
	}
	for _, path := range files {
		input, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		compareLoadedScan(t, control, loaded, input)
	}
}

func BenchmarkSecretsLiteralGuard(b *testing.B) {
	db, control, root := literalGuardExperiment(b)
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
		for _, variant := range []struct {
			name string
			db   *Database
		}{{"control", control}, {"guard", db}} {
			b.Run(filepath.Base(path)+"/"+variant.name, func(b *testing.B) {
				scratch := NewScratch(variant.db)
				handler := func(Match) error { return nil }
				if err := variant.db.Scan(input, scratch, handler); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(len(input)))
				b.ReportAllocs()
				for b.Loop() {
					if err := variant.db.Scan(input, scratch, handler); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
