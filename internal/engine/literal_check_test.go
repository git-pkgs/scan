package engine

import (
	"regexp"
	"testing"
)

func TestLiteralCheckPreservesCaseAndPunctuation(t *testing.T) {
	cases := []struct{ expression, input string }{
		{`(?i)\[foo\]`, "[FoO]"},
		{`(?i)alpha_key`, "ALpha_KeY"},
		{`CaseSensitive!Token`, "CaseSensitive!Token"},
		{`(?i)finicity`, "FiNiCiTy"},
	}
	for _, test := range cases {
		db, err := Compile(&Pattern{Expression: test.expression, Flags: SingleMatch | SomLeftMost})
		if err != nil {
			t.Fatal(err)
		}
		reference := regexp.MustCompile(test.expression)
		scratch := NewScratch(db)
		for position := -1; position < len(test.input); position++ {
			for _, replacement := range []byte{'A', 'a', '[', '{', ']', '}', 0xff, 0, ':', ' '} {
				data := []byte("prefix " + test.input + " suffix")
				if position >= 0 {
					data[len("prefix ")+position] = replacement
				}
				want := reference.FindIndex(data)
				var got []Match
				if err := db.Scan(data, scratch, func(m Match) error {
					got = append(got, m)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if len(got) == 0 && want != nil || len(got) != 0 && (want == nil || got[0].From != uint64(want[0]) || got[0].To != uint64(want[1])) {
					t.Fatalf("%s on %q: got %v, want %v", test.expression, data, got, want)
				}
			}
		}
	}
}
