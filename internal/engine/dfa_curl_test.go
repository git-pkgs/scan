package engine

import (
	"os"
	"path/filepath"
	"regexp/syntax"
	"testing"
	"time"
)

func curlDFAExperiment(tb testing.TB) (*Database, *Database, string) {
	tb.Helper()
	rules, root := loadSecretsRules(tb)
	db := compileSecretsRules(tb, rules)
	control := *db
	control.patterns = append([]compiledPattern(nil), db.patterns...)
	for i, rule := range rules {
		if rule.id != "curl-auth-header" && rule.id != "curl-auth-user" {
			continue
		}
		p := &db.patterns[i]
		atoms, accelerated := requiredAtoms(p.source.Expression, p.source.Flags)
		if !accelerated || p.source.Flags.has(UTF8) {
			tb.Fatal("anchored experiment requires byte-mode literal triggers")
		}
		for _, atom := range atoms {
			if atom.prefixMin < 0 || atom.prefixMin != atom.prefixMax {
				tb.Fatal("anchored experiment requires exact-start windows")
			}
		}
		parsed, err := parseExpression(rule.expression, p.source.Flags)
		if err != nil {
			tb.Fatal(err)
		}
		prog, err := syntax.Compile(dfaExpression(parsed).Simplify())
		if err != nil {
			tb.Fatal(err)
		}
		tb.Logf("%s: instructions=%d nullable=%v defaultDFA=%v", rule.id, len(prog.Inst), nullable(dfaExpression(parsed)), p.dfa != nil)
		for _, limit := range []int{1024, 2048, 8192} {
			started := time.Now()
			dfa := compileRejectDFAWithLimit(parsed, p.source.Flags, limit)
			if dfa == nil {
				tb.Logf("%s: limit=%d failed in %s", rule.id, limit, time.Since(started))
				continue
			}
			tb.Logf("%s: limit=%d states=%d bytes=%d compile=%s", rule.id, limit, len(dfa.next)/dfa.stride, (len(dfa.next)+len(dfa.search))*2, time.Since(started))
			p.dfa = dfa
			break
		}
		if p.dfa == nil {
			started := time.Now()
			p.dfa = compileRejectDFA(relaxCurlRepeats(parsed), p.source.Flags)
			if p.dfa != nil {
				tb.Logf("%s: relaxed states=%d compile=%s", rule.id, len(p.dfa.next)/p.dfa.stride, time.Since(started))
			} else {
				tb.Logf("%s: relaxed failed in %s", rule.id, time.Since(started))
			}
		}
		if p.dfa == nil {
			for _, limit := range []int{512, 8192} {
				started := time.Now()
				p.dfa = experimentalAnchoredDFA(parsed, limit)
				if p.dfa != nil {
					tb.Logf("%s: anchored states=%d compile=%s", rule.id, len(p.dfa.next)/p.dfa.stride, time.Since(started))
					break
				}
				tb.Logf("%s: anchored limit=%d failed in %s", rule.id, limit, time.Since(started))
			}
		}
		started := time.Now()
		if dfa := experimentalAnchoredDFA(relaxCurlRepeats(parsed), 8192); dfa != nil {
			tb.Logf("%s: relaxed anchored states=%d compile=%s", rule.id, len(dfa.next)/dfa.stride, time.Since(started))
			p.dfa = dfa
		} else {
			tb.Logf("%s: relaxed anchored failed in %s", rule.id, time.Since(started))
		}
	}
	triggers := append(append([]trigger(nil), db.matcher.hashed.triggers...), db.matcher.hashPairs.triggers...)
	db.size = estimateSize(db, triggers)
	return db, &control, root
}

func experimentalAnchoredDFA(expression *syntax.Regexp, limit int) *rejectDFA {
	prog, err := syntax.Compile(dfaExpression(expression).Simplify())
	if err != nil || len(prog.Inst) > maxDFAProgram {
		return nil
	}
	b := dfaBuilder{prog: prog, masks: compileByteMasks(prog), ids: make(map[string]uint16), limit: limit}
	words := (len(prog.Inst) + dfaWordBits - 1) / dfaWordBits
	b.closures = make([][]uint64, len(prog.Inst))
	for pc := range prog.Inst {
		if prog.Inst[pc].Op == syntax.InstMatch {
			b.matchPC = pc
		}
		b.closures[pc] = dfaClosure(prog, uint32(pc), words)
	}
	b.initial = b.closures[prog.Start]
	if b.initial[b.matchPC/dfaWordBits]&(uint64(1)<<(b.matchPC%dfaWordBits)) != 0 {
		return nil
	}
	b.states = []dfaState{{bits: b.initial}, {}, {bits: make([]uint64, words)}}
	b.ids[dfaStateKey(b.initial)+"a"] = 0
	b.ids[dfaStateKey(b.states[dfaDead].bits)+"a"] = dfaDead
	classes, alphabet := dfaAlphabet(b.masks, words)
	dfa := &rejectDFA{classes: classes, stride: len(alphabet)}
	for state := 0; state < len(b.states); state++ {
		dfa.next = append(dfa.next, make([]uint16, len(alphabet))...)
		dfa.search = append(dfa.search, make([]uint16, len(alphabet))...)
		if state == dfaAccept {
			continue
		}
		active := b.states[state]
		for class, value := range alphabet {
			id, ok := b.intern(b.advance(active.bits, value), false)
			if !ok {
				return nil
			}
			dfa.next[state*dfa.stride+class] = id
			dfa.search[state*dfa.stride+class] = id
		}
	}
	return dfa
}

func relaxCurlRepeats(expression *syntax.Regexp) *syntax.Regexp {
	copy := *expression
	copy.Sub = make([]*syntax.Regexp, len(expression.Sub))
	for i, child := range expression.Sub {
		copy.Sub[i] = relaxCurlRepeats(child)
	}
	if copy.Op == syntax.OpRepeat {
		copy.Min = min(copy.Min, 1)
		copy.Max = -1
	}
	return &copy
}

func TestCurlAnchoredDFA(t *testing.T) {
	db, control, root := curlDFAExperiment(t)
	loaded, _ := roundTripDatabase(t, db)
	files := []string{filepath.Join(root, "main.go"), filepath.Join(root, "betterleaks/config/betterleaks.toml"), filepath.Join(root, "secrets")}
	if directory := os.Getenv("SCAN_DIAGNOSTIC_DIR"); directory != "" {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			files = append(files, filepath.Join(directory, entry.Name()))
		}
	}
	for _, path := range files {
		input, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		compareLoadedScan(t, control, loaded, input)
	}
}

func BenchmarkCurlAnchoredDFA(b *testing.B) {
	db, control, root := curlDFAExperiment(b)
	files := []string{filepath.Join(root, "betterleaks/config/betterleaks.toml")}
	if blob := os.Getenv("SCAN_DIAGNOSTIC_BLOB"); blob != "" {
		files = append(files, blob)
	}
	for _, path := range files {
		input, err := os.ReadFile(path)
		if err != nil {
			b.Fatal(err)
		}
		for _, variant := range []struct {
			name string
			db   *Database
		}{{"control", control}, {"anchored_relaxed", db}} {
			b.Run(filepath.Base(path)+"/"+variant.name, func(b *testing.B) {
				scratch := NewScratch(variant.db)
				handler := func(Match) error { return nil }
				if err := variant.db.Scan(input, scratch, handler); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(len(input)))
				b.ReportAllocs()
				for b.Loop() {
					if err := variant.db.Scan(input, scratch, handler); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
