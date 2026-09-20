package engine

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

const azureStorageExpression = `(?i)\b(?:AccountKey|(?:azure[_\s.-]*)?(?:storage[_\s.-]*)?(?:account[_\s.-]*)?(?:access[_\s.-]*)?key)\b(?s:.{0,24}?)([A-Za-z0-9+/]{86}==)`

func withoutAtomStartConstraints(tb testing.TB, db *Database) *Database {
	tb.Helper()
	control := *db
	control.patterns = append([]compiledPattern(nil), db.patterns...)
	for i := range control.patterns {
		p := &control.patterns[i]
		re, err := parseExpression(p.source.Expression, p.source.Flags)
		if err != nil {
			tb.Fatal(err)
		}
		p.start = leadingStartConstraint(re, !p.source.Flags.has(UTF8))
	}
	return &control
}

func TestAtomStartConstraints(t *testing.T) {
	expressions := []string{
		azureStorageExpression,
		`(?:ab*KEY|cd*KEY)[0-9]{3}`,
		`(?:ab*KEY|xy+KEY)[0-9]{3}`,
		`(?:a*key)+end`,
		`(?i)(?:az[_ .-]*)?key[^!]*!`,
		`(?:x?y*)?needle.*end`,
		`(?i)\xB5*key`,
		`(?s).*key`,
		`.*key`,
		`a*key(?s:.{0,8})[0-9]{24}==`,
		`a*key(?s:.{0,240})[0-9]{32}==`,
		`(?:a*b|c*d)key[0-9]{24}==`,
	}
	for _, flags := range []Flags{SomLeftMost, SomLeftMost | SingleMatch, SomLeftMost | Caseless, SomLeftMost | UTF8} {
		patterns := make([]*Pattern, len(expressions))
		for i, expression := range expressions {
			patterns[i] = &Pattern{Expression: expression, ID: uint(i), Flags: flags}
		}
		db, err := Compile(patterns...)
		if err != nil {
			t.Fatal(err)
		}
		if !flags.has(UTF8) && db.patterns[0].start.kind != startWithinClass {
			t.Fatal("Azure prefix was not bounded")
		}
		if db.patterns[7].start.kind != startUnbounded {
			t.Fatal("all-byte prefix must remain unbounded")
		}
		control := withoutAtomStartConstraints(t, db)
		loaded, _ := roundTripDatabase(t, db)
		token := string(bytes.Repeat([]byte{'A'}, 86)) + "=="
		samples := []string{"KEY123", "abbbbKEY123", "cddddKEY789", "xyyyyKEY456", "aaakeykeyend", "az_ .--KEY!!!", "xneedlexend", "\xb5\xb5key", "µµkey", "\nkey", "AccountKey=" + token, "AZURE_storage.account_access KEY=" + token, "key=short key=" + token}
		for _, sample := range samples {
			for cut := 0; cut <= len(sample); cut++ {
				input := []byte("{\"value\":\"" + sample[:cut] + "\"}")
				compareLoadedScan(t, control, db, input)
				compareLoadedScan(t, control, loaded, input)
			}
		}
		for value := 0; value < 256; value++ {
			input := append([]byte("azure"), bytes.Repeat([]byte{byte(value)}, 32)...)
			input = append(input, []byte("key="+token)...)
			compareLoadedScan(t, control, loaded, input)
		}
		for _, separators := range []int{0, 1, 96, 256, 512} {
			for _, gap := range []int{0, 1, 23, 24, 25} {
				input := append([]byte("prefix:AZURE"), bytes.Repeat([]byte{'_'}, separators)...)
				input = append(input, []byte("key")...)
				input = append(input, bytes.Repeat([]byte{0}, gap)...)
				input = append(input, token...)
				compareLoadedScan(t, control, loaded, input)
			}
		}
		rng := rand.New(rand.NewSource(103))
		for trial := 0; trial < 1500; trial++ {
			input := make([]byte, rng.Intn(512))
			_, _ = rng.Read(input)
			if len(input) > 0 {
				copy(input[rng.Intn(len(input)):], samples[rng.Intn(len(samples))])
			}
			compareLoadedScan(t, control, loaded, input)
		}
	}
}

func TestAtomStartConstraintTailLimit(t *testing.T) {
	for _, gap := range []int{0, 8, 240, 256} {
		expression := `a*key(?s:.{0,` + fmt.Sprint(gap) + `})[0-9]{32}==`
		db, err := Compile(&Pattern{Expression: expression, Flags: SomLeftMost})
		if err != nil {
			t.Fatal(err)
		}
		if (db.patterns[0].start.kind == startWithinClass) != (gap < 240) {
			t.Fatalf("gap=%d: constraint=%+v", gap, db.patterns[0].start)
		}
		control := withoutAtomStartConstraints(t, db)
		loaded, _ := roundTripDatabase(t, db)
		input := append([]byte("!aaaakey"), bytes.Repeat([]byte{0}, gap)...)
		input = append(input, bytes.Repeat([]byte{'1'}, 32)...)
		input = append(input, '=', '=')
		compareLoadedScan(t, control, loaded, input)
		matched, err := loaded.Match(input, nil)
		if err != nil || !matched {
			t.Fatalf("gap=%d: Match=%v, %v", gap, matched, err)
		}
	}
}

func TestAtomStartConstraintSkipsClosures(t *testing.T) {
	db, err := Compile(&Pattern{Expression: azureStorageExpression, Flags: SingleMatch | SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	loaded, _ := roundTripDatabase(t, db)
	control := withoutAtomStartConstraints(t, db)
	input := bytes.Repeat([]byte(`{"name":"ordinary registry metadata","version":"1.2.3"}`), 8192)
	input = append(input, []byte(`{"key":"ordinary"}`)...)
	input = append(input, bytes.Repeat([]byte{'A'}, 86)...)
	input = append(input, '=', '=')
	for _, candidate := range []*Database{db, loaded} {
		compareLoadedScan(t, control, candidate, input)
		fast, slow := NewScratch(candidate), NewScratch(control)
		if _, err := candidate.Match(input, fast); err != nil {
			t.Fatal(err)
		}
		if _, err := control.Match(input, slow); err != nil {
			t.Fatal(err)
		}
		if slow.nfa.generation < uint32(len(input)) || fast.nfa.generation >= slow.nfa.generation/2 {
			t.Fatalf("closures: bounded=%d unbounded=%d", fast.nfa.generation, slow.nfa.generation)
		}
	}
}

func TestSecretsAtomStartConstraints(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	control := withoutAtomStartConstraints(t, db)
	loaded, _ := roundTripDatabase(t, db)
	for i, pattern := range db.patterns {
		if pattern.start != control.patterns[i].start {
			t.Logf("bounded %s with %d prefix bytes", rules[i].id, pattern.start.mask.count())
		}
	}
	for _, name := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml", "hyperscan.db", "secrets"} {
		input, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		compareLoadedScan(t, control, loaded, input)
	}
	if directory := os.Getenv("SCAN_DIAGNOSTIC_DIR"); directory != "" {
		files, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			input, err := os.ReadFile(filepath.Join(directory, file.Name()))
			if err != nil {
				t.Fatal(err)
			}
			compareLoadedScan(t, control, loaded, input)
		}
	}
}

func BenchmarkSecretsAtomStartConstraints(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	control := withoutAtomStartConstraints(b, db)
	files := []string{filepath.Join(root, "main.go"), filepath.Join(root, "betterleaks/detect/detect.go"), filepath.Join(root, "betterleaks/config/betterleaks.toml"), filepath.Join(root, "secrets")}
	if blob := os.Getenv("SCAN_DIAGNOSTIC_BLOB"); blob != "" {
		files = append(files, blob)
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			b.Fatal(err)
		}
		for _, variant := range []struct {
			name string
			db   *Database
		}{{"control", control}, {"bounded", db}} {
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
