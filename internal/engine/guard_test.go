package engine

import (
	"bytes"
	"math/rand"
	"regexp"
	"testing"
)

func TestRunGuardScanAcrossRejectedBytes(t *testing.T) {
	const expression = `(?i)token[=: ]{0,24}[a-f0-9]{12}(?:!|$)`
	db, err := Compile(&Pattern{Expression: expression, Flags: SingleMatch | SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(expression)
	scratch := NewScratch(db)
	for gap := 0; gap <= 26; gap++ {
		for bad := -1; bad <= 12; bad++ {
			data := append([]byte("prefix TOKEN"), bytes.Repeat([]byte{'='}, gap)...)
			token := []byte("ABCDEF012345!")
			if bad >= 0 {
				token[bad] = '#'
			}
			data = append(data, token...)
			var got []Match
			if err := db.Scan(data, scratch, func(m Match) error {
				got = append(got, m)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			want := re.FindIndex(data)
			if len(got) == 0 && want != nil || len(got) > 0 && (want == nil || got[0].From != uint64(want[0]) || got[0].To != uint64(want[1])) {
				t.Fatalf("Scan(%q) = %v, want %v", data, got, want)
			}
		}
	}
}

func TestMaskedRunSkippingMatchesLinearSearch(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var lookup [256]bool
	lookup['a'], lookup['b'] = true, true
	for iteration := 0; iteration < 20000; iteration++ {
		data := make([]byte, 1+rng.Intn(160))
		for i := range data {
			data[i] = "aaaab#"[rng.Intn(6)]
		}
		guard := runGuard{lookup: &lookup, length: 1 + rng.Intn(40)}
		first := rng.Intn(len(data))
		last := first + rng.Intn(len(data)-first)
		want := false
		for start := first; start <= last && start+guard.length <= len(data); start++ {
			matched := true
			for _, value := range data[start : start+guard.length] {
				matched = matched && lookup[value]
			}
			want = want || matched
		}
		if got := containsMaskedRun(data, first, last, &guard); got != want {
			t.Fatalf("data=%q bounds=%d:%d length=%d: got %v, want %v", data, first, last, guard.length, got, want)
		}
	}
}
