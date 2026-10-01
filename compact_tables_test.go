package scan_test

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"

	"github.com/git-pkgs/scan"
)

func TestCompactTables(t *testing.T) {
	db, err := scan.Compile(
		&scan.Pattern{Expression: `TOKEN=[a-z0-9]{8}`, ID: 1, Flags: scan.SingleMatch | scan.SomLeftMost},
		&scan.Pattern{Expression: `(?i:ab)`, ID: 2, Flags: scan.SingleMatch | scan.SomLeftMost},
		&scan.Pattern{Expression: `[A-F][0-9]`, ID: 3, Flags: scan.SingleMatch | scan.SomLeftMost},
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Captured from the dense-table implementation.
	const checksum = "3f1a59634bcf2f13e40f3107bb4db62f28f9cc501f1b302456b4c40f5724f8f9"
	if got := fmt.Sprintf("%x", sha256.Sum256(encoded)); got != checksum {
		t.Fatalf("serialized database changed: %s", got)
	}
	loaded, err := scan.UnmarshalDatabase(encoded)
	if err != nil {
		t.Fatal(err)
	}
	want := []scan.Match{{ID: 1, From: 7, To: 21}, {ID: 2, From: 22, To: 24}, {ID: 3, From: 25, To: 27}}
	input := []byte("prefix TOKEN=12345678 AB F9 suffix")
	for _, candidate := range []*scan.Database{db, loaded} {
		if candidate.Size() >= 64*1024 {
			t.Fatalf("small database retains %d bytes", candidate.Size())
		}
		var got []scan.Match
		if err := candidate.Scan(input, scan.NewScratch(candidate), func(m scan.Match) error {
			got = append(got, m)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("matches=%v want=%v", got, want)
		}
		if found, err := candidate.Match(input, nil); err != nil || !found {
			t.Fatalf("Match=%t, %v", found, err)
		}
	}
}
