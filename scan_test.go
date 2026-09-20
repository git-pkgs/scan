package scan_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/git-pkgs/scan"
)

func TestPublicScratchReuseAcrossDatabases(t *testing.T) {
	small, err := scan.Compile(&scan.Pattern{Expression: "x"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		expression string
		input      string
		flags      scan.Flags
	}{
		{"byte", `token=[a-z0-9]{64}`, "token=" + strings.Repeat("a", 64), 0},
		{"utf8", `token=é{64}`, "token=" + strings.Repeat("é", 64), scan.UTF8},
	} {
		t.Run(test.name, func(t *testing.T) {
			large, err := scan.Compile(&scan.Pattern{Expression: test.expression, ID: 7, Flags: test.flags | scan.SomLeftMost | scan.SingleMatch}, &scan.Pattern{Expression: "absent", ID: 8})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := large.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := scan.UnmarshalDatabase(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for _, db := range []*scan.Database{large, loaded} {
				for _, scratch := range []*scan.Scratch{scan.NewScratch(small), scan.NewScratch(small).Clone(), new(scan.Scratch)} {
					for range 2 {
						var got []scan.Match
						if err := db.Scan([]byte(test.input), scratch, func(m scan.Match) error { got = append(got, m); return nil }); err != nil {
							t.Fatal(err)
						}
						want := []scan.Match{{ID: 7, To: uint64(len(test.input))}}
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("matches=%v want=%v", got, want)
						}
						if matched, err := db.Match([]byte(test.input), scratch); err != nil || !matched {
							t.Fatalf("large Match=%v error=%v", matched, err)
						}
						if matched, err := small.Match([]byte("x"), scratch); err != nil || !matched {
							t.Fatalf("small Match=%v error=%v", matched, err)
						}
					}
				}
			}
		})
	}
}

func TestPublicDatabaseRoundTrip(t *testing.T) {
	pattern := scan.NewPattern(`token=[a-z0-9]{8}`, scan.Caseless|scan.SingleMatch|scan.SomLeftMost)
	pattern.ID = 17
	if !pattern.Valid() || scan.NewPattern(`(`, 0).Valid() {
		t.Fatal("unexpected pattern validation")
	}
	db, err := scan.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	stats := db.Stats()
	if stats.Patterns != 1 || db.Size() <= 0 {
		t.Fatalf("stats=%+v size=%d", stats, db.Size())
	}
	artifact, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := scan.UnmarshalDatabase(artifact)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("prefix TOKEN=abc12345 suffix")
	for _, database := range []*scan.Database{db, loaded} {
		scratch := scan.NewScratch(database).Clone()
		var got []scan.Match
		var handler scan.MatchHandler = func(match scan.Match) error {
			got = append(got, match)
			return nil
		}
		if err := database.Scan(input, scratch, handler); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, []scan.Match{{ID: 17, From: 7, To: 21}}) {
			t.Fatalf("events=%v", got)
		}
		matched, err := database.Match(input, scratch)
		if err != nil || !matched {
			t.Fatalf("Match=%v, %v", matched, err)
		}
		err = database.Scan(input, scratch, func(scan.Match) error { return scan.ErrScanTerminated })
		if !errors.Is(err, scan.ErrScanTerminated) {
			t.Fatalf("termination=%v", err)
		}
	}
	if _, err := scan.Compile(); !errors.Is(err, scan.ErrInvalid) {
		t.Fatalf("empty compilation=%v", err)
	}
}
