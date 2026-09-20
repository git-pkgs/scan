package engine

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func roundTripDatabase(tb testing.TB, db *Database) (*Database, []byte) {
	tb.Helper()
	encoded, err := db.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	loaded, err := UnmarshalDatabase(encoded)
	if err != nil {
		tb.Fatal(err)
	}
	if got, want := loaded.Stats(), db.Stats(); got != want {
		tb.Fatalf("stats = %+v, want %+v", got, want)
	}
	if loaded.Size() != db.Size() {
		tb.Fatalf("size = %d, want %d", loaded.Size(), db.Size())
	}
	for i := range db.patterns {
		if !reflect.DeepEqual(db.patterns[i].loops, loaded.patterns[i].loops) {
			tb.Fatalf("pattern %d loop tables changed on round trip", i)
		}
	}
	again, err := loaded.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	if !bytes.Equal(encoded, again) {
		tb.Fatal("compiled tables changed on round trip")
	}
	return loaded, encoded
}

func compareLoadedScan(tb testing.TB, db, loaded *Database, input []byte) {
	tb.Helper()
	var original, restored []Match
	if err := db.Scan(input, NewScratch(db), func(m Match) error { original = append(original, m); return nil }); err != nil {
		tb.Fatal(err)
	}
	if err := loaded.Scan(input, NewScratch(loaded), func(m Match) error { restored = append(restored, m); return nil }); err != nil {
		tb.Fatal(err)
	}
	if !reflect.DeepEqual(original, restored) {
		tb.Fatalf("loaded events %v != compiled events %v", restored, original)
	}
	matched, err := loaded.Match(input, NewScratch(loaded))
	if err != nil || matched != (len(original) != 0) {
		tb.Fatalf("loaded Match = %v, %v; original events=%v", matched, err, original)
	}
}

func TestCompiledTablesRoundTrip(t *testing.T) {
	patterns := []*Pattern{
		{Expression: `token=[a-z0-9]{8,20}`, ID: 3, Flags: SomLeftMost},
		{Expression: `(?i)shared-literal-[0-9]+`, ID: 5, Flags: SingleMatch},
		{Expression: `\bxy\b`, ID: 7, Flags: SomLeftMost},
		{Expression: `[0-9]{15}\|[a-z0-9_-]{27}`, ID: 9, Flags: SomLeftMost},
		{Expression: `a*`, ID: 11, Flags: AllowEmpty | SomLeftMost},
		{Expression: `é.界`, ID: 13, Flags: UTF8 | SomLeftMost},
		{Expression: `^line.+$`, ID: 15, Flags: MultiLine | DotAll | SomLeftMost},
		{Expression: `xy[^z]*z`, ID: 17, Flags: SomLeftMost},
	}
	db, err := Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	loaded, encoded := roundTripDatabase(t, db)
	clear(encoded)
	sample := []byte("token=abcdefgh shared-LITERAL-123 xy xyz é!界\nline hello\n123456789012345|abcdefghijklmnopqrstuvwxyz_")
	for length := 0; length <= len(sample); length++ {
		compareLoadedScan(t, db, loaded, sample[:length])
	}
	rng := rand.New(rand.NewSource(61))
	for i := 0; i < 200; i++ {
		data := make([]byte, rng.Intn(100))
		_, _ = rng.Read(data)
		compareLoadedScan(t, db, loaded, data)
	}
}

func TestCompiledDatabaseDoesNotParseSource(t *testing.T) {
	db, err := Compile(&Pattern{Expression: `token=[a-z]+`, ID: 99, Flags: SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	db.patterns[0].source.Expression = string(bytes.Repeat([]byte{'('}, len(db.patterns[0].source.Expression)))
	loaded, _ := roundTripDatabase(t, db)
	compareLoadedScan(t, db, loaded, []byte("token=secret"))
	matched, err := loaded.Match([]byte("token=secret"), nil)
	if err != nil || !matched {
		t.Fatalf("Match = %v, %v", matched, err)
	}
}

func sealDatabase(data []byte) {
	sum := sha256.Sum256(data[databaseHeaderSize:])
	copy(data[len(databaseMagic):databaseHeaderSize], sum[:])
}

func TestCompiledDatabaseRejectsCorruption(t *testing.T) {
	db, err := Compile(&Pattern{Expression: "needle"})
	if err != nil {
		t.Fatal(err)
	}
	_, encoded := roundTripDatabase(t, db)
	old := bytes.Clone(encoded)
	copy(old, "SCANDB\x00\x04")
	if _, err := UnmarshalDatabase(old); !errors.Is(err, ErrInvalid) {
		t.Fatalf("old database version accepted: %v", err)
	}
	for _, data := range [][]byte{nil, {}, []byte(`{"format":1,"patterns":[]}`), encoded[:databaseHeaderSize-1]} {
		if _, err := UnmarshalDatabase(data); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid format error = %v", err)
		}
	}
	for _, offset := range []int{0, len(databaseMagic) - 1, databaseHeaderSize, len(encoded) / 2, len(encoded) - 1} {
		bad := bytes.Clone(encoded)
		bad[offset] ^= 1
		if _, err := UnmarshalDatabase(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("corrupt byte %d: %v", offset, err)
		}
	}
	for length := databaseHeaderSize; length < len(encoded); length += 7919 {
		bad := bytes.Clone(encoded[:length])
		sealDatabase(bad)
		if _, err := UnmarshalDatabase(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("truncated length %d: %v", length, err)
		}
	}
	bad := append(bytes.Clone(encoded), 0)
	sealDatabase(bad)
	if _, err := UnmarshalDatabase(bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing bytes: %v", err)
	}
	bad = bytes.Clone(encoded)
	for i := databaseHeaderSize; i < databaseHeaderSize+4; i++ {
		bad[i] = 255
	}
	sealDatabase(bad)
	if _, err := UnmarshalDatabase(bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized count: %v", err)
	}
	if _, err := (*Database)(nil).Marshal(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil Marshal: %v", err)
	}
}

func TestSecretsCompiledDatabase(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	loaded, encoded := roundTripDatabase(t, db)
	t.Logf("artifact bytes=%d database bytes=%d", len(encoded), loaded.Size())
	if loaded.matcher.fdr == nil {
		t.Fatal("FDR table was not restored")
	}
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml", "hyperscan.db", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		t.Run(filepath.Base(path), func(t *testing.T) { compareLoadedScan(t, db, loaded, data) })
	}
}

func TestCompiledDatabaseRejectsInvalidTables(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Database)
	}{
		{"start", func(db *Database) { db.patterns[0].prog.Start = -1 }},
		{"instruction-target", func(db *Database) { db.patterns[0].prog.Inst[1].Out = ^uint32(0) }},
		{"instruction-op", func(db *Database) { db.patterns[0].prog.Inst[1].Op = 255 }},
		{"flags", func(db *Database) { db.patterns[0].source.Flags = ^Flags(0) }},
		{"closure-index", func(db *Database) { db.patterns[0].epsilonAt[1] = ^uint32(0) }},
		{"closure-target", func(db *Database) { db.patterns[0].epsilon[0] = ^uint32(0) }},
		{"start-closure", func(db *Database) { db.patterns[0].startClosures.offsets[64]++ }},
		{"loop-length", func(db *Database) { db.patterns[0].loops = make([]*[256]bool, 1) }},
		{"loop-transition", func(db *Database) {
			p := &db.patterns[0]
			p.loops = make([]*[256]bool, len(p.prog.Inst))
			p.loops[0] = new([256]bool)
			p.loops[0]['a'] = true
		}},
		{"width", func(db *Database) { db.patterns[0].width = -2 }},
		{"guard", func(db *Database) { db.patterns[0].guards[0].length = -1 }},
		{"dfa-stride", func(db *Database) { db.patterns[0].dfa.stride = 0 }},
		{"dfa-state", func(db *Database) { db.patterns[0].dfa.next[0] = ^uint16(0) }},
		{"bucket", func(db *Database) { db.matcher.hashed.buckets[0].group = ^uint32(0) }},
		{"group", func(db *Database) { db.matcher.hashed.groups[0].checkAt = -1 }},
		{"always", func(db *Database) { db.always = []uint32{^uint32(0)} }},
		{"pattern-id", func(db *Database) { db.matcher.hashed.triggers[0].pattern = ^uint32(0) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, err := Compile(&Pattern{Expression: `needle[a-z]{8}`})
			if err != nil {
				t.Fatal(err)
			}
			test.change(db)
			encoded, err := db.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalDatabase(encoded); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid tables: %v", err)
			}
		})
	}
}

func FuzzCompiledDatabase(f *testing.F) {
	db, err := Compile(&Pattern{Expression: `needle[a-z]{8}`, Flags: SomLeftMost})
	if err != nil {
		f.Fatal(err)
	}
	_, encoded := roundTripDatabase(f, db)
	f.Add(encoded)
	f.Add([]byte(databaseMagic))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			t.Skip()
		}
		if len(data) >= databaseHeaderSize {
			data = bytes.Clone(data)
			sealDatabase(data)
		}
		loaded, err := UnmarshalDatabase(data)
		if err != nil {
			return
		}
		for _, input := range [][]byte{nil, []byte("needleabcdefgh"), {0, 255, '\n'}} {
			if err := loaded.Scan(input, nil, func(Match) error { return nil }); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestEmbeddedDatabaseExecutable(t *testing.T) {
	if testing.Short() {
		t.Skip("builds an embedded standalone executable")
	}
	db, err := Compile(&Pattern{Expression: `token=[a-z]{8}`, ID: 42, Flags: SingleMatch | SomLeftMost})
	if err != nil {
		t.Fatal(err)
	}
	_, artifact := roundTripDatabase(t, db)
	dir := t.TempDir()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Dir(filepath.Dir(root))
	files := map[string][]byte{
		"go.mod":        []byte(fmt.Sprintf("module embeddedscan\n\ngo 1.26.0\n\nrequire github.com/git-pkgs/scan v0.0.0\nreplace github.com/git-pkgs/scan => %s\n", root)),
		"database.scan": artifact,
		"main.go": []byte(`package main
import (
    _ "embed"
    "fmt"
    "os"
    scan "github.com/git-pkgs/scan"
)
//go:embed database.scan
var artifact []byte
func main() {
    db, err := scan.UnmarshalDatabase(artifact)
    if err != nil { panic(err) }
    input, err := os.ReadFile(os.Args[1])
    if err != nil { panic(err) }
    if err := db.Scan(input, scan.NewScratch(db), func(m scan.Match) error {
        fmt.Printf("%d:%d:%d\n", m.ID, m.From, m.To)
        return nil
    }); err != nil { panic(err) }
}`),
		"input.txt": []byte("prefix token=abcdefgh suffix"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "build", "-o", "scanner", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	cmd = exec.Command(filepath.Join(dir, "scanner"), filepath.Join(dir, "input.txt"))
	output, err := cmd.CombinedOutput()
	if err != nil || string(output) != "42:7:21\n" {
		t.Fatalf("embedded scan: %v, %q", err, output)
	}
}

func BenchmarkSecretsDatabaseStartup(b *testing.B) {
	rules, _ := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	_, encoded := roundTripDatabase(b, db)
	b.Logf("artifact bytes=%d database bytes=%d", len(encoded), db.Size())
	b.Run("compile", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			compileSecretsRules(b, rules)
		}
	})
	b.Run("load", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := UnmarshalDatabase(encoded); err != nil {
				b.Fatal(err)
			}
		}
	})
}
