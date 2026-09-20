package engine

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

type secretsRule struct {
	id         string
	expression string
	re         *regexp.Regexp
}

func loadSecretsRules(tb testing.TB) ([]secretsRule, string) {
	tb.Helper()
	root := os.Getenv("SECRETS_ROOT")
	if root == "" {
		root = filepath.Join("..", "..", "..", "secrets")
	}
	path := filepath.Join(root, "betterleaks", "config", "betterleaks.toml")
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		tb.Skipf("secrets corpus is unavailable at %s", path)
	}
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	var rules []secretsRule
	var id string
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "id = \"") {
			id = strings.TrimSuffix(strings.TrimPrefix(line, "id = \""), "\"")
			continue
		}
		if !strings.HasPrefix(line, "regex = '''") || !strings.HasSuffix(line, "'''") {
			continue
		}
		expression := strings.TrimSuffix(strings.TrimPrefix(line, "regex = '''"), "'''")
		re, err := regexp.Compile(expression)
		if err != nil {
			tb.Fatalf("compile secrets rule %q: %v", id, err)
		}
		rules = append(rules, secretsRule{id: id, expression: expression, re: re})
	}
	if err := scanner.Err(); err != nil {
		tb.Fatal(err)
	}
	if len(rules) < 400 {
		tb.Fatalf("loaded %d secrets rules, want at least 400", len(rules))
	}
	return rules, root
}

func compileSecretsRules(tb testing.TB, rules []secretsRule) *Database {
	tb.Helper()
	patterns := make([]*Pattern, len(rules))
	for i, rule := range rules {
		patterns[i] = &Pattern{
			Expression: rule.expression,
			Flags:      SingleMatch | AllowEmpty | SomLeftMost,
			ID:         uint(i),
		}
	}
	db, err := Compile(patterns...)
	if err != nil {
		tb.Fatal(err)
	}
	return db
}

func TestSecretsRulesMatchRegexp(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	t.Logf("compile stats: %+v, database bytes: %d", db.Stats(), db.Size())
	if os.Getenv("SCAN_DIAGNOSTICS") != "" {
		lengths := make(map[int]int)
		literalTriggers := append([]trigger(nil), db.matcher.hashed.triggers...)
		for _, trigger := range db.matcher.hashPairs.triggers {
			if len(trigger.text) > 0 {
				literalTriggers = append(literalTriggers, trigger)
			}
		}
		for _, trigger := range literalTriggers {
			lengths[min(len(trigger.text), 8)]++
		}
		t.Logf("literal lengths capped at 8: %v", lengths)
		for _, trigger := range db.matcher.hashPairs.triggers {
			if len(trigger.masks) == 0 {
				continue
			}
			atoms, _ := requiredAtoms(rules[trigger.pattern].expression, 0)
			t.Logf("mask trigger: %s masks=%d atoms=%v", rules[trigger.pattern].id, len(trigger.masks), atoms)
		}
	}

	paths := []string{
		filepath.Join(root, "main.go"),
		filepath.Join(root, "scan.go"),
		filepath.Join(root, "betterleaks", "detect", "detect.go"),
		filepath.Join(root, "betterleaks", "detect", "detect_test.go"),
		filepath.Join(root, "betterleaks", "config", "betterleaks.toml"),
		filepath.Join(root, "betterleaks", "testdata", "repos", "nogit", "api.go"),
		filepath.Join(root, "betterleaks", "testdata", "repos", "nogit", ".env.prod"),
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			scratch := NewScratch(db)
			if err := scratch.prepare(len(db.patterns)); err != nil {
				t.Fatal(err)
			}
			for _, pattern := range db.always {
				scratch.addCandidate(pattern)
			}
			db.matcher.scan(data, scratch)
			t.Logf("bytes=%d candidates=%d hits=%d", len(data), len(scratch.candidates), len(scratch.hits))
			if os.Getenv("SCAN_DIAGNOSTICS") != "" {
				hitCounts := make(map[uint32]int)
				for _, hit := range scratch.hits {
					hitCounts[hit.pattern]++
				}
				for _, index := range scratch.candidates {
					started := time.Now()
					matched := rules[index].re.Match(data)
					atoms, _ := requiredAtoms(rules[index].expression, 0)
					maskAtoms, maskOK := requiredMaskAtoms(rules[index].expression, 0)
					maskCost, maskLength := maskAtomScore(maskAtoms)
					useMasks := maskOK && (len(atoms) == 0 || hasUnboundedAtoms(atoms) && maskLength >= shortestAtom(atoms)+4)
					single := compileSecretsRules(t, []secretsRule{rules[index]})
					singleStarted := time.Now()
					if err := single.Scan(data, NewScratch(single), func(Match) error { return nil }); err != nil {
						t.Fatal(err)
					}
					t.Logf("candidate=%s program=%d width=%d hits=%d matched=%v regexp=%s scan=%s atoms=%v masks=%v/%d cost=%d length=%d selected=%v guards=%v", rules[index].id, len(db.patterns[index].prog.Inst), db.patterns[index].width, hitCounts[index], matched, time.Since(started), time.Since(singleStarted), atoms, maskOK, len(maskAtoms), maskCost, maskLength, useMasks, db.patterns[index].guards)
				}
			}
			scratch.release()
			assertSameRuleMatches(t, db, rules, data)
		})
	}
}

func TestSecretsRulesMatchRegexpAtChunkBoundaries(t *testing.T) {
	rules, _ := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	inputs := [][]byte{
		[]byte(`awsToken := "AKIALALEMEL33243OLIA"`),
		[]byte(`github_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"`),
		[]byte("-----BEGIN PRIVATE KEY-----\nYWJjZGVmZ2hpamtsbW5vcA==\n-----END PRIVATE KEY-----"),
	}
	for padding := 0; padding < 32; padding++ {
		for _, input := range inputs {
			data := append(bytes.Repeat([]byte{'x'}, padding), input...)
			data = append(data, bytes.Repeat([]byte{'y'}, 31-padding)...)
			assertSameRuleMatches(t, db, rules, data)
		}
	}
}

func TestSecretsLargeBlobDiagnostics(t *testing.T) {
	if os.Getenv("SCAN_LARGE_DIAGNOSTICS") == "" {
		t.Skip("set SCAN_LARGE_DIAGNOSTICS=1")
	}
	rules, root := loadSecretsRules(t)
	db, rules := diagnosticDatabase(t, rules)
	relative := os.Getenv("SCAN_DIAGNOSTIC_FILE")
	if relative == "" {
		relative = "secrets"
	}
	path := filepath.Join(root, relative)
	if blob := os.Getenv("SCAN_DIAGNOSTIC_BLOB"); blob != "" {
		path = blob
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	scratch := NewScratch(db)
	if err := scratch.prepare(len(db.patterns)); err != nil {
		t.Fatal(err)
	}
	defer scratch.release()
	db.matcher.scan(data, scratch)
	t.Logf("bytes=%d candidates=%d hits=%d hit_capacity=%d", len(data), len(scratch.candidates), len(scratch.hits), cap(scratch.hits))
	type patternTiming struct {
		pattern      uint32
		hits         int
		windows      int
		startSlots   uint64
		maxStartSpan int
		closures     uint64
		unbounded    bool
		duration     time.Duration
	}
	var timings []patternTiming
	for _, pattern := range scratch.candidates {
		first := scratch.hitHeads[pattern]
		if first < 0 {
			continue
		}
		compiled := &db.patterns[pattern]
		hits := 0
		unbounded := false
		for current := first; current >= 0; current = scratch.hits[current].next {
			hits++
			unbounded = unbounded || scratch.hits[current].unbounded && compiled.start.kind == startUnbounded
		}
		result := patternTiming{pattern: pattern, hits: hits, unbounded: unbounded}
		scanWindow := func(start, end, startMin, startMax int) error {
			span := max(0, min(end, startMax)-max(start, startMin)+1)
			result.windows++
			result.startSlots += uint64(span)
			result.maxStartSpan = max(result.maxStartSpan, span)
			before := scratch.nfa.generation
			err := db.scanPattern(data, start, end, pattern, scratch, func(Match) error { return nil }, startMin, startMax)
			result.closures += diagnosticClosureCount(before, scratch.nfa.generation)
			return err
		}
		started := time.Now()
		if unbounded {
			err = scanWindow(0, len(data), 0, len(data))
		} else {
			for current := first; current >= 0; current = scratch.hits[current].next {
				hit := scratch.hits[current]
				startMin, startMax := int(hit.startMin), int(hit.startMax)
				if hit.unbounded {
					var ok bool
					startMin, startMax, ok = compiled.start.bounds(data, int(hit.atomStart), startMax)
					if !ok {
						continue
					}
				}
				end := len(data)
				if compiled.width >= 0 {
					end = min(end, startMax+compiled.width)
				}
				err = scanWindow(startMin, end, startMin, startMax)
				if err != nil || compiled.source.Flags.has(SingleMatch) && scratch.reported[pattern] == scratch.generation {
					break
				}
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		result.duration = time.Since(started)
		timings = append(timings, result)
	}
	sort.Slice(timings, func(left, right int) bool { return timings[left].duration > timings[right].duration })
	for rank, result := range timings[:min(30, len(timings))] {
		compiled := db.patterns[result.pattern]
		regexpDuration := time.Duration(0)
		regexpMatched := false
		if rank < 3 {
			started := time.Now()
			regexpMatched = rules[result.pattern].re.Match(data)
			regexpDuration = time.Since(started)
		}
		t.Logf("%s pattern=%d duration=%s hits=%d windows=%d start_slots=%d max_start_span=%d nfa_closures=%d unbounded=%v program=%d width=%d guards=%d dfa=%v regexp=%s matched=%v",
			rules[result.pattern].id, result.pattern, result.duration, result.hits, result.windows, result.startSlots, result.maxStartSpan, result.closures, result.unbounded,
			len(compiled.prog.Inst), compiled.width, len(compiled.guards), compiled.dfa != nil, regexpDuration, regexpMatched)
	}
}

func diagnosticClosureCount(before, after uint32) uint64 {
	count := uint64(after - before)
	if after < before {
		count-- // Generation zero is skipped on wraparound.
	}
	return count
}

func TestDiagnosticClosureCount(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `a*z`, Flags: SingleMatch})
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("aaaaaz")
	for _, generation := range []uint32{0, 1, ^uint32(0) - 2} {
		scratch := NewScratch(db)
		scratch.nfa.generation = generation
		matched, err := db.Match(input, scratch)
		if err != nil || !matched {
			t.Fatalf("Match=%v, %v", matched, err)
		}
		if got := diagnosticClosureCount(generation, scratch.nfa.generation); got != uint64(len(input)+1) {
			t.Fatalf("generation=%d: closure count=%d, want %d", generation, got, len(input)+1)
		}
	}
}

func diagnosticDatabase(t *testing.T, rules []secretsRule) (*Database, []secretsRule) {
	t.Helper()
	path := os.Getenv("SCAN_DIAGNOSTIC_DATABASE")
	if path == "" {
		return compileSecretsRules(t, rules), rules
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := UnmarshalDatabase(data)
	if err != nil {
		t.Fatal(err)
	}
	byExpression := make(map[string]secretsRule)
	for _, rule := range rules {
		byExpression[rule.expression] = rule
	}
	loadedRules := make([]secretsRule, len(db.patterns))
	for i, pattern := range db.patterns {
		rule, ok := byExpression[pattern.source.Expression]
		if !ok {
			rule = secretsRule{id: fmt.Sprintf("pattern-%d", i), expression: pattern.source.Expression, re: regexp.MustCompile(pattern.source.Expression)}
		}
		if !pattern.source.Flags.has(SingleMatch) {
			rule.id += "/all-matches"
		}
		loadedRules[i] = rule
	}
	return db, loadedRules
}

func TestDiagnosticDatabaseLabels(t *testing.T) {
	expression := `token=[a-z]{3}`
	db, err := Compile(&Pattern{Expression: expression, ID: 6, Flags: SingleMatch}, &Pattern{Expression: expression, ID: 9})
	if err != nil {
		t.Fatal(err)
	}
	data, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "database.scan")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCAN_DIAGNOSTIC_DATABASE", path)
	rules := []secretsRule{{id: "token", expression: expression, re: regexp.MustCompile(expression)}}
	loaded, labels := diagnosticDatabase(t, rules)
	if len(labels) != 2 || labels[0].id != "token" || labels[1].id != "token/all-matches" {
		t.Fatalf("unexpected diagnostic labels: %v", labels)
	}
	compareLoadedScan(t, db, loaded, []byte("token=abc token=def"))
}

func assertSameRuleMatches(t *testing.T, db *Database, rules []secretsRule, data []byte) {
	t.Helper()
	got := make([]bool, len(rules))
	err := db.Scan(data, NewScratch(db), func(match Match) error {
		got[match.ID] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var differences []string
	for i, rule := range rules {
		want := rule.re.Match(data)
		if got[i] != want {
			differences = append(differences, fmt.Sprintf("%s: got %v, want %v", rule.id, got[i], want))
		}
	}
	if len(differences) > 0 {
		sort.Strings(differences)
		t.Fatalf("rule match differences:\n%s", strings.Join(differences, "\n"))
	}
}

func BenchmarkSecretsRules(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	for _, relative := range []string{
		"main.go",
		"secrets",
		filepath.Join("betterleaks", "detect", "detect.go"),
		filepath.Join("betterleaks", "config", "betterleaks.toml"),
	} {
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(filepath.Base(relative), func(b *testing.B) {
			scratch := NewScratch(db)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				if err := db.Scan(data, scratch, func(Match) error { return nil }); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestSecretsWarmScanAllocations(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	data, err := os.ReadFile(filepath.Join(root, "betterleaks", "detect", "detect.go"))
	if err != nil {
		t.Fatal(err)
	}
	scratch := NewScratch(db)
	allocations := testing.AllocsPerRun(20, func() {
		if err := db.Scan(data, scratch, func(Match) error { return nil }); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("warm scan allocations = %v, want 0", allocations)
	}
}
