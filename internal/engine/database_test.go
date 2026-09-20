package engine

import (
	"bytes"
	"errors"
	"math/rand"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

func TestScanReportsPatternMatches(t *testing.T) {
	patterns := []*Pattern{
		{Expression: `AKIA[0-9A-Z]{16}`, Flags: SingleMatch | SomLeftMost, ID: 10},
		{Expression: `(?i)token[[:space:]]*=[[:space:]]*[a-z0-9]+`, Flags: SingleMatch | SomLeftMost, ID: 20},
		{Expression: `[0-9]{4}-[0-9]{4}`, Flags: SomLeftMost, ID: 30},
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("token = abc123\nAKIA1234567890ABCDEF\ncode 1234-5678")
	var matches []Match
	err = db.Scan(data, NewScratch(db), func(match Match) error {
		matches = append(matches, match)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })
	want := []Match{
		{ID: 10, From: 15, To: 35},
		{ID: 20, From: 0, To: 9},
		{ID: 30, From: 41, To: 50},
	}
	if !reflect.DeepEqual(matches, want) {
		t.Fatalf("matches = %#v, want %#v", matches, want)
	}
}

func TestLargeBlockHashMatcherMatchesRegexp(t *testing.T) {
	const blockSize = 1 << 20
	patterns := []*Pattern{
		{Expression: `SensitiveNeedle-[0-9]{4}`, Flags: SingleMatch | SomLeftMost, ID: 1},
		{Expression: `(?i)CaseLessNeedle-[a-f0-9]{4}`, Flags: SingleMatch | SomLeftMost, ID: 2},
		{Expression: `xy[0-9]{2}`, Flags: SingleMatch | SomLeftMost, ID: 3},
		{Expression: `[0-9]{15}\|[a-z0-9_-]{27}`, Flags: SingleMatch | SomLeftMost, ID: 4},
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.matcher.hashed.triggers) == 0 || len(db.matcher.hashPairs.triggers) == 0 {
		t.Fatalf("large-block matchers were not compiled")
	}
	data := bytes.Repeat([]byte{' '}, blockSize+4096)
	samples := []struct {
		offset int
		text   string
	}{
		{offset: 1021, text: "SensitiveNeedle-2048"},
		{offset: 65539, text: "caselessneedle-dead"},
		{offset: blockSize - 3, text: "xy42"},
		{offset: blockSize + 1024, text: "123456789012345|abcdefghijklmnopqrstuvwxyz_"},
	}
	for _, sample := range samples {
		copy(data[sample.offset:], sample.text)
	}

	got := make(map[uint]Match)
	err = db.Scan(data, NewScratch(db), func(match Match) error {
		got[match.ID] = match
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range patterns {
		location := regexp.MustCompile(pattern.Expression).FindIndex(data)
		if location == nil {
			t.Fatalf("reference expression %d did not match", pattern.ID)
		}
		want := Match{ID: pattern.ID, From: uint64(location[0]), To: uint64(location[1])}
		if got[pattern.ID] != want {
			t.Fatalf("match %d = %#v, want %#v", pattern.ID, got[pattern.ID], want)
		}
	}
}

func TestScanReportsEveryEndOffset(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `aa`, ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	var ends []uint64
	err = db.Scan([]byte("aaaa"), NewScratch(db), func(match Match) error {
		ends = append(ends, match.To)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint64{2, 3, 4}; !reflect.DeepEqual(ends, want) {
		t.Fatalf("end offsets = %v, want %v", ends, want)
	}
}

func TestUTF8FlagChangesDotFromByteToRune(t *testing.T) {
	input := []byte("é")
	for _, test := range []struct {
		name  string
		flags Flags
		ends  []uint64
	}{
		{name: "byte", ends: []uint64{1, 2}},
		{name: "utf8", flags: UTF8, ends: []uint64{2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, err := Compile(&Pattern{Expression: `.`, Flags: test.flags})
			if err != nil {
				t.Fatal(err)
			}
			var ends []uint64
			err = db.Scan(input, NewScratch(db), func(match Match) error {
				ends = append(ends, match.To)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ends, test.ends) {
				t.Fatalf("end offsets = %v, want %v", ends, test.ends)
			}
		})
	}
}

func TestScanDoesNotDropAlternatives(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `(alpha|bravo)-[0-9]+`, ID: 7, Flags: SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"alpha-1", "bravo-2"} {
		matched, err := db.Match([]byte(input), NewScratch(db))
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Fatalf("%q did not match", input)
		}
	}
}

func TestSingleMatch(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `key`, ID: 4, Flags: SingleMatch | SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	var matches []Match
	err = db.Scan([]byte("key key"), NewScratch(db), func(match Match) error {
		matches = append(matches, match)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].From != 0 || matches[0].To != 3 {
		t.Fatalf("matches = %#v", matches)
	}
}

func TestScratchRejectsConcurrentUse(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `test`})
	if err != nil {
		t.Fatal(err)
	}
	scratch := NewScratch(db)
	if err := scratch.prepare(1); err != nil {
		t.Fatal(err)
	}
	defer scratch.release()
	if err := db.Scan([]byte("test"), scratch, func(Match) error { return nil }); !errors.Is(err, ErrScratchInUse) {
		t.Fatalf("Scan error = %v, want %v", err, ErrScratchInUse)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `secret-[0-9]+`, ID: 99, Flags: SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	data, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalDatabase(data)
	if err != nil {
		t.Fatal(err)
	}
	var got Match
	err = restored.Scan([]byte("a secret-42 z"), NewScratch(restored), func(match Match) error {
		got = match
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := (Match{ID: 99, From: 2, To: 11}); got != want {
		t.Fatalf("match = %#v, want %#v", got, want)
	}
}

func TestCompileRejectsEmptyMatch(t *testing.T) {
	_, err := Compile(&Pattern{Expression: `a*`})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Compile error = %v, want %v", err, ErrInvalid)
	}
	if _, err := Compile(&Pattern{Expression: `a*`, Flags: AllowEmpty}); err != nil {
		t.Fatal(err)
	}
}

func TestCompileUsesClassMaskWithoutRequiredLiteral(t *testing.T) {
	expression := `(?i)\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	atoms, ok := requiredMaskAtoms(expression, 0)
	if !ok {
		parsed, err := parseExpression(expression, 0)
		if err != nil {
			t.Fatal(err)
		}
		raw, rawOK := maskAtomsFor(parsed.Simplify(), true)
		lengths := make([]int, len(raw))
		for index := range raw {
			lengths[index] = len(raw[index].masks)
		}
		t.Fatalf("requiredMaskAtoms failed: raw ok=%v lengths=%v", rawOK, lengths)
	}
	if len(atoms) == 0 || len(atoms[0].masks) < 8 {
		t.Fatalf("mask atoms = %#v", atoms)
	}
}

func TestByteModeMaskUsesASCIIPortionOfFoldedClass(t *testing.T) {
	expression := `(?i)key.{0,24}?([A-Za-z0-9+/]{86}==)`
	atoms, ok := requiredMaskAtoms(expression, 0)
	if !ok || len(atoms) != 1 || len(atoms[0].masks) != maxMaskLength {
		t.Fatalf("byte-mode mask atoms = %#v, %v", atoms, ok)
	}
	if !atoms[0].masks[maxMaskLength-2].contains('=') || !atoms[0].masks[maxMaskLength-1].contains('=') {
		t.Fatalf("mask does not include fixed suffix: %#v", atoms[0])
	}
	utf8Atoms, utf8OK := requiredMaskAtoms(expression, UTF8)
	if !utf8OK || len(utf8Atoms) != 1 || len(utf8Atoms[0].masks) != 2 {
		t.Fatalf("UTF-8 mask atoms = %#v, %v", utf8Atoms, utf8OK)
	}
}

func TestRunGuardRejectsKeywordWithoutCredentialShape(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `(?i)secret.{0,5}[A-Z0-9]{12}`})
	if err != nil {
		t.Fatal(err)
	}
	if len(db.patterns[0].guards) != 1 {
		t.Fatalf("run guards = %#v", db.patterns[0].guards)
	}
	for input, want := range map[string]bool{
		"secret = ordinary":          false,
		"secret = ABCD1234EFGH":      true,
		"prefix secret ABCD1234EFGH": true,
	} {
		got, err := db.Match([]byte(input), NewScratch(db))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("Match(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestCompileFindsLeadingStartConstraints(t *testing.T) {
	patterns := []*Pattern{
		{Expression: `\{[^{]+"private_key"[^}]+\}`},
		{Expression: `\b([a-zA-Z0-9_-]+-[a-zA-Z0-9_-]+-PRD-[a-f0-9]{8})`},
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	if db.patterns[0].start.kind != startAfterByte || db.patterns[0].start.value != '{' {
		t.Fatalf("delimiter constraint = %#v", db.patterns[0].start)
	}
	if db.patterns[1].start.kind != startWithinClass {
		t.Fatalf("class constraint = %#v", db.patterns[1].start)
	}
	for input, want := range map[string]bool{
		`prefix { ignored { "private_key":"value" } suffix`: true,
		`prefix private_key without braces`:                 false,
	} {
		matched, err := db.Match([]byte(input), NewScratch(db))
		if err != nil {
			t.Fatal(err)
		}
		if matched != want {
			t.Fatalf("Match(%q) = %v, want %v", input, matched, want)
		}
	}
	matched, err := db.Match([]byte(`prefix user-name-PRD-deadbeef suffix`), NewScratch(db))
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("class-bounded pattern did not match")
	}
}

func TestHyperscanBlockMatchOrdering(t *testing.T) {
	patterns := []*Pattern{
		{Expression: `aa`, Flags: DotAll, ID: 1},
		{Expression: `aa.`, Flags: DotAll, ID: 2},
		{Expression: `aa..`, Flags: DotAll, ID: 3},
		{Expression: `^.{0,4}aa..`, Flags: DotAll, ID: 4},
		{Expression: `^.{0,4}aa`, Flags: DotAll, ID: 5},
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[uint]int)
	lastEnd := uint64(0)
	err = db.Scan([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), NewScratch(db), func(match Match) error {
		if match.To < lastEnd {
			t.Fatalf("match end %d followed %d", lastEnd, match.To)
		}
		lastEnd = match.To
		counts[match.ID]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint]int{1: 31, 2: 30, 3: 29, 4: 5, 5: 5}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("match counts = %v, want %v", counts, want)
	}
}

func TestHyperscanMultiPatternEventsAndTermination(t *testing.T) {
	patterns := []*Pattern{
		{Expression: `aoo[A-K]`, ID: 30},
		{Expression: `bar[L-Z]`, ID: 31},
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	var matches []Match
	err = db.Scan([]byte("aooAaooAbarZ"), NewScratch(db), func(match Match) error {
		matches = append(matches, match)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []Match{{ID: 30, To: 4}, {ID: 30, To: 8}, {ID: 31, To: 12}}
	if !reflect.DeepEqual(matches, want) {
		t.Fatalf("matches = %#v, want %#v", matches, want)
	}
	count := 0
	err = db.Scan([]byte("aooAaooAbarZ"), NewScratch(db), func(Match) error {
		count++
		return ErrScanTerminated
	})
	if !errors.Is(err, ErrScanTerminated) || count != 1 {
		t.Fatalf("terminated scan = %v with %d callbacks", err, count)
	}
}

func TestScanEndOffsetsAgainstRegexpExhaustiveSubstrings(t *testing.T) {
	expressions := []string{
		`ab`,
		`a+b`,
		`a{2,4}b`,
		`(?:ab|ba)c`,
		`[a-c]{2,4}d`,
		`a.?b`,
		`(?:foo|bar)[0-9]{2}`,
		`a[^x]{1,3}b`,
		`(?i)token`,
	}
	patterns := make([]*Pattern, len(expressions))
	references := make([]*regexp.Regexp, len(expressions))
	for index, expression := range expressions {
		patterns[index] = &Pattern{Expression: expression, Flags: SomLeftMost, ID: uint(index)}
		references[index] = regexp.MustCompile(`\A(?:` + expression + `)\z`)
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewSource(1))
	alphabet := []byte("abcdfokent012x ")
	for iteration := 0; iteration < 200; iteration++ {
		data := make([]byte, 64)
		for index := range data {
			data[index] = alphabet[random.Intn(len(alphabet))]
		}
		var got []Match
		err := db.Scan(data, NewScratch(db), func(match Match) error {
			got = append(got, match)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		var want []Match
		for end := 1; end <= len(data); end++ {
			for pattern, reference := range references {
				from := -1
				for start := 0; start <= end; start++ {
					if reference.Match(data[start:end]) {
						from = start
						break
					}
				}
				if from >= 0 {
					want = append(want, Match{ID: uint(pattern), From: uint64(from), To: uint64(end)})
				}
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("iteration %d input %q\nmatches = %#v\nwant    = %#v", iteration, data, got, want)
		}
	}
}

func TestAllowEmptyReportsEveryOffset(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `a*`, Flags: AllowEmpty | SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	var matches []Match
	err = db.Scan([]byte("bb"), NewScratch(db), func(match Match) error {
		matches = append(matches, match)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []Match{{From: 0, To: 0}, {From: 1, To: 1}, {From: 2, To: 2}}
	if !reflect.DeepEqual(matches, want) {
		t.Fatalf("matches = %#v, want %#v", matches, want)
	}
}

func TestSnowflakeTriggerExtraction(t *testing.T) {
	expression := `(?i:(?:(?:snowflake[_. -]*(?:programmatic[_. -]*)?(?:access[_. -]*)?token|sf[_. -]*token))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{100,500})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	atoms, ok := requiredAtoms(expression, 0)
	if !ok {
		t.Fatal("requiredAtoms failed")
	}
	want := [][]byte{[]byte("sf"), []byte("snowflake")}
	if len(atoms) != len(want) {
		t.Fatalf("atoms = %#v", atoms)
	}
	for index := range want {
		if !reflect.DeepEqual(atoms[index].text, want[index]) || !atoms[index].caseless || atoms[index].prefixMin != 0 || atoms[index].prefixMax != 0 {
			t.Fatalf("atoms = %#v", atoms)
		}
	}
}
