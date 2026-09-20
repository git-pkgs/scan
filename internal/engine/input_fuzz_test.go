package engine

import (
	"bytes"
	"reflect"
	"testing"
)

func FuzzSecretsScan(f *testing.F) {
	rules, _ := loadSecretsRules(f)
	db := compileSecretsRules(f, rules)
	loaded, _ := roundTripDatabase(f, db)
	control := *db
	control.patterns = append([]compiledPattern(nil), db.patterns...)
	for i := range control.patterns {
		control.patterns[i].literalGuard = nil
	}
	f.Add([]byte{})
	f.Add([]byte("package main\nfunc main() {}\n"))
	f.Add([]byte(`curl -H "Authorization: Bearer abcdefgh12345678"`))
	f.Add([]byte("curl\n\n\n\n\n -u 'example:abcdefgh'\n"))
	f.Add(append([]byte("curl "), bytes.Repeat([]byte{'x'}, maxLiteralGuardBytes+1)...))
	f.Add(bytes.Repeat([]byte{'A'}, 256))
	f.Add([]byte{0, 255, 128, '\r', '\n', 'c', 'u', 'r', 'l', 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		scratch := new(Scratch)
		var reference []Match
		for i, candidate := range []*Database{&control, db, loaded} {
			var matches []Match
			if err := candidate.Scan(input, scratch, func(match Match) error {
				if match.From > match.To || match.To > uint64(len(input)) || match.ID >= uint(len(rules)) {
					t.Fatalf("invalid match offsets or ID: %+v input length=%d", match, len(input))
				}
				matches = append(matches, match)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				reference = matches
			} else if !reflect.DeepEqual(matches, reference) {
				t.Fatalf("variant %d: matches=%v reference=%v", i, matches, reference)
			}
			matched, err := candidate.Match(input, scratch)
			if err != nil || matched != (len(reference) != 0) {
				t.Fatalf("variant %d: Match=%v error=%v events=%d", i, matched, err, len(reference))
			}
		}
	})
}
