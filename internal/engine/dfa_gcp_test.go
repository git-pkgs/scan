package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp/syntax"
	"testing"
	"time"
)

func gcpDFAExperiment(tb testing.TB) (*Database, *Database, string) {
	tb.Helper()
	rules, root := loadSecretsRules(tb)
	db := compileSecretsRules(tb, rules)
	control := *db
	control.patterns = append([]compiledPattern(nil), db.patterns...)
	for i, rule := range rules {
		if rule.id != "gcp-service-account" && rule.id != "gcp-application-default-credentials" {
			continue
		}
		parsed, err := parseExpression(rule.expression, db.patterns[i].source.Flags)
		if err != nil {
			tb.Fatal(err)
		}
		prog, err := syntax.Compile(dfaExpression(parsed).Simplify())
		if err != nil {
			tb.Fatal(err)
		}
		tb.Logf("%s: instructions=%d nullable=%v defaultDFA=%v", rule.id, len(prog.Inst), nullable(dfaExpression(parsed)), db.patterns[i].dfa != nil)
		for _, limit := range []int{1024, 2048, 8192} {
			start := time.Now()
			dfa := compileRejectDFAWithLimit(parsed, db.patterns[i].source.Flags, limit)
			if dfa == nil {
				tb.Logf("%s: limit=%d failed in %s", rule.id, limit, time.Since(start))
				continue
			}
			tb.Logf("%s: limit=%d states=%d tableBytes=%d compile=%s", rule.id, limit, len(dfa.next)/dfa.stride, (len(dfa.next)+len(dfa.search))*2, time.Since(start))
			db.patterns[i].dfa = dfa
			break
		}
	}
	return db, &control, root
}

func TestGCPRaisedDFALimit(t *testing.T) {
	db, control, root := gcpDFAExperiment(t)
	for _, path := range []string{"main.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml", "hyperscan.db", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		var got, want []Match
		if err := db.Scan(data, NewScratch(db), func(m Match) error { got = append(got, m); return nil }); err != nil {
			t.Fatal(err)
		}
		if err := control.Scan(data, NewScratch(control), func(m Match) error { want = append(want, m); return nil }); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: raised DFA=%v control=%v", path, got, want)
		}
	}
}

func BenchmarkGCPRaisedDFALimit(b *testing.B) {
	db, control, root := gcpDFAExperiment(b)
	for _, path := range []string{"hyperscan.db", "betterleaks/config/betterleaks.toml"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			b.Fatal(err)
		}
		for _, variant := range []struct {
			name string
			db   *Database
		}{{"default", control}, {"raised", db}} {
			b.Run(filepath.Base(path)+"/"+variant.name, func(b *testing.B) {
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
