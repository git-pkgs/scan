package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMatchStopsResidualWork(t *testing.T) {
	for _, first := range []string{`token`, `[a-z]+`} {
		db, err := Compile(&Pattern{Expression: first, ID: 1}, &Pattern{Expression: `secret[0-9]+`, ID: 2})
		if err != nil {
			t.Fatal(err)
		}
		scratch := NewScratch(db)
		data := []byte("token secret123 secret456")
		for repeat := 0; repeat < 3; repeat++ {
			matched, err := db.Match(data, scratch)
			if err != nil || !matched {
				t.Fatalf("Match(%q) = %v, %v", data, matched, err)
			}
			if scratch.collectFor != 0 || len(scratch.matches) != 0 {
				t.Fatalf("continued after first match: pattern=%d queued=%d", scratch.collectFor, len(scratch.matches))
			}
			if first == `[a-z]+` && len(scratch.hits) != 0 {
				t.Fatal("literal dispatch ran after an always-run pattern matched")
			}
			var ids = make(map[uint]bool)
			if err := db.Scan(data, scratch, func(match Match) error { ids[match.ID] = true; return nil }); err != nil {
				t.Fatal(err)
			}
			if len(ids) != 2 {
				t.Fatalf("Scan after Match reported %v", ids)
			}
			matched, err = db.Match([]byte("1234"), scratch)
			if err != nil || matched {
				t.Fatalf("negative Match = %v, %v", matched, err)
			}
		}
	}
}

func TestMatchSecretsAgainstRegexp(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	scratch := NewScratch(db)
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		want := false
		for _, rule := range rules {
			if rule.re.Match(data) {
				want = true
				break
			}
		}
		got, err := db.Match(data, scratch)
		if err != nil || got != want {
			t.Fatalf("Match(%s) = %v, %v; want %v", path, got, err, want)
		}
	}
}

func TestIsASCIIWordBoundaries(t *testing.T) {
	for padding := 0; padding < 16; padding++ {
		for length := 0; length < 40; length++ {
			data := bytes.Repeat([]byte{'A'}, padding+length)[padding:]
			if !isASCII(data) {
				t.Fatalf("rejected ASCII at alignment=%d length=%d", padding, length)
			}
			for position := range data {
				for value := 128; value < 256; value++ {
					data[position] = byte(value)
					if isASCII(data) {
						t.Fatalf("accepted byte=%x at alignment=%d position=%d length=%d", value, padding, position, length)
					}
				}
				data[position] = 'A'
			}
		}
	}
}

func TestScanUTF8Candidates(t *testing.T) {
	db, err := Compile(
		&Pattern{Expression: `.{2}needle`, Flags: UTF8 | SingleMatch | SomLeftMost, ID: 1},
		&Pattern{Expression: `plain`, Flags: SingleMatch, ID: 2},
	)
	if err != nil {
		t.Fatal(err)
	}
	scratch := NewScratch(db)
	for _, input := range []string{"é界needle plain", "abneedle plain", "plain", "é界needle", "absent"} {
		want := bytes.Contains([]byte(input), []byte("needle"))
		found := false
		if err := db.Scan([]byte(input), scratch, func(match Match) error {
			if match.ID == 1 {
				found = true
				if match.From != 0 {
					t.Fatalf("Scan(%q) = %+v", input, match)
				}
			}
			return nil
		}); err != nil || found != want {
			t.Fatalf("Scan(%q) found=%v want=%v err=%v", input, found, want, err)
		}
	}
}

func BenchmarkSecretsMatch(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			b.Fatal(err)
		}
		for _, ordered := range []bool{true, false} {
			name := "Match"
			if ordered {
				name = "Scan"
			}
			b.Run(filepath.Base(path)+"/"+name, func(b *testing.B) {
				scratch := NewScratch(db)
				if _, err := db.Match(data, scratch); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					if ordered {
						err = db.Scan(data, scratch, func(Match) error { return ErrScanTerminated })
						if err != nil && err != ErrScanTerminated {
							b.Fatal(err)
						}
					} else if _, err := db.Match(data, scratch); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
