package engine

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
)

func TestDFAScanMatchesNFA(t *testing.T) {
	expressions := []string{
		`ab+c`, `ab{2,5}c`, `ab.*cd`, `(?:ab|bc)+c`, `(?i)ab[c-f]+`,
		`\bab\b`, `^ab$`, `(?m)^ab$`, `ab\Bc`, `(?:ab|cd)?`,
		`[ab]{8,12}cd`, `key.{0,4}ab+c`, `(?:ab|cde)f?`, `a.*?b`,
		`ab[^c]*cd`, `(?:\b|c)ab`, `(?:ab)*`, `ab[\x80-\xff]+`,
	}
	patterns := make([]*Pattern, len(expressions))
	for i, expression := range expressions {
		patterns[i] = &Pattern{Expression: expression, ID: uint(i), Flags: AllowEmpty | SomLeftMost}
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	baseline := *db
	baseline.patterns = append([]compiledPattern(nil), db.patterns...)
	for i := range baseline.patterns {
		if db.patterns[i].dfa == nil && !nullableMustParse(expressions[i]) {
			t.Fatalf("DFA missing for %s", expressions[i])
		}
		baseline.patterns[i].dfa = nil
	}
	scratch, baselineScratch := NewScratch(db), NewScratch(&baseline)
	rng := rand.New(rand.NewSource(12))
	const alphabet = "aaabbcdefkey AB_\n\x80\xff"
	for iteration := 0; iteration < 1000; iteration++ {
		data := make([]byte, rng.Intn(100))
		for i := range data {
			data[i] = alphabet[rng.Intn(len(alphabet))]
		}
		var got, want []Match
		if err := db.Scan(data, scratch, func(m Match) error {
			got = append(got, m)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := baseline.Scan(data, baselineScratch, func(m Match) error {
			want = append(want, m)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Scan(%q) = %v, NFA = %v", data, got, want)
		}
	}
}

func TestDFAScanBeyondRejectionLimit(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `ab.*cd`, Flags: SomLeftMost | SingleMatch})
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte("ab"), bytes.Repeat([]byte{'x'}, maxDFARejectBytes*2)...)
	data = append(data, 'c', 'd')
	var matches []Match
	if err := db.Scan(data, NewScratch(db), func(m Match) error {
		matches = append(matches, m)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].From != 0 || matches[0].To != uint64(len(data)) {
		t.Fatalf("matches = %v", matches)
	}
}

func nullableMustParse(expression string) bool {
	parsed, err := parseExpression(expression, 0)
	return err == nil && nullable(parsed)
}
