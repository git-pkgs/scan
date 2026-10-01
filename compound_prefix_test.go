package scan_test

import (
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/git-pkgs/scan"
)

const (
	repeatedDelimiterInput = "<abc:<defTOKEN"
	foldedDelimiterPattern = `(?i:a)b+:TOKEN`
)

func TestCompoundUnboundedPrefixes(t *testing.T) {
	for _, tt := range []struct{ expression, input string }{
		{`\{[^{]+"private_key"[^}]+\}`, `prefix { "private_key":"{value" } suffix`},
		{`\{[^{]+"private_key"[^{}]+\}`, `prefix { ignored { "private_key":"value" } suffix`},
		{`(?m)^\s+\w+\s+=>\s`, "    source => "},
		{`(?m)^\s+\w+\s+=>\s`, "# header\n    source => value"},
		{`^a+Xb+TOKEN`, "aaaXbbbTOKEN"},
		{`^\d+ +TOKEN`, "123  TOKEN"},
		{`^[a-z]+:[0-9]+:[A-Z]+TOKEN`, "name:123:VALUETOKEN"},
		{`<[a-z]+:[^>]+TOKEN`, repeatedDelimiterInput},
		{`^<[a-z]+:[^>]+TOKEN`, repeatedDelimiterInput},
		{`(<)([a-z]+):(?:x|<)+TOKEN`, "prefix <abc:x<xTOKEN"},
		{`<[a-z]+:<[a-z]+TOKEN`, repeatedDelimiterInput},
		{`(?i)a[b]+:[^>]+TOKEN`, "abb:xaTOKEN"},
		{foldedDelimiterPattern, "abbb:TOKEN"},
		{foldedDelimiterPattern, "Abbb:TOKEN"},
		{`<[a-z]+:[^<>]+TOKEN`, "<bad:> <abc:defTOKEN"},
	} {
		for _, flags := range []scan.Flags{scan.SingleMatch, scan.SingleMatch | scan.SomLeftMost, scan.SingleMatch | scan.SomLeftMost | scan.UTF8} {
			t.Run(fmt.Sprintf("%s/%d", tt.expression, flags), func(t *testing.T) {
				db, err := scan.Compile(&scan.Pattern{Expression: tt.expression, ID: 7, Flags: flags})
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := db.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				loaded, err := scan.UnmarshalDatabase(encoded)
				if err != nil {
					t.Fatal(err)
				}
				control := regexp.MustCompile(tt.expression)
				for _, candidate := range []*scan.Database{db, loaded} {
					assertCompoundPrefixes(t, candidate, control, tt.input, flags)
				}
			})
		}
	}
}

func FuzzCompoundPrefixes(f *testing.F) {
	expressions := []string{`<[a-z]+:[^>]+TOKEN`, `^<[a-z]+:[^>]+TOKEN`, `(<)([a-z]+):(?:x|<)+TOKEN`, `<[a-z]+:<[a-z]+TOKEN`, foldedDelimiterPattern, `\s+\w+\s+=>\s`}
	patterns := make([]*scan.Pattern, len(expressions))
	controls := make([]*regexp.Regexp, len(expressions))
	for i, expression := range expressions {
		patterns[i] = &scan.Pattern{Expression: expression, ID: uint(i), Flags: scan.SingleMatch}
		controls[i] = regexp.MustCompile(expression)
	}
	db, err := scan.Compile(patterns...)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"", repeatedDelimiterInput, "prefix <abc:x<xTOKEN", "abbb:TOKEN", "Abbb:TOKEN", "    source => ", "<bad:> <abc:defTOKEN"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		matched := make([]bool, len(expressions))
		if err := db.Scan(input, scan.NewScratch(db), func(match scan.Match) error {
			matched[match.ID] = true
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		runes := make([]rune, len(input))
		for i, value := range input {
			runes[i] = rune(value)
		}
		for i, control := range controls {
			if want := control.MatchString(string(runes)); matched[i] != want {
				t.Errorf("pattern %q input %q: got %t want %t", expressions[i], input, matched[i], want)
			}
		}
	})
}

func assertCompoundPrefixes(t *testing.T, candidate *scan.Database, control *regexp.Regexp, source string, flags scan.Flags) {
	t.Helper()
	scratch := scan.NewScratch(candidate)
	for cut := 0; cut <= len(source); cut++ {
		input := []byte(source[:cut])
		location := control.FindIndex(input)
		var got, want []scan.Match
		if location != nil {
			from := uint64(0)
			if flags&scan.SomLeftMost != 0 {
				from = uint64(location[0])
			}
			want = []scan.Match{{ID: 7, From: from, To: uint64(location[1])}}
		}
		if err := candidate.Scan(input, scratch, func(match scan.Match) error { got = append(got, match); return nil }); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: Scan=%v want=%v", input, got, want)
		}
		if matched, err := candidate.Match(input, scratch); err != nil || matched != (location != nil) {
			t.Errorf("%q: Match=%t error=%v", input, matched, err)
		}
	}
}
