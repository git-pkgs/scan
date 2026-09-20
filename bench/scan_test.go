package bench

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/flier/gohs/hyperscan"
	scan "github.com/git-pkgs/scan"
)

func loadPatterns(tb testing.TB, includeNative bool) ([]*scan.Pattern, []*hyperscan.Pattern) {
	tb.Helper()
	root := os.Getenv("SECRETS_ROOT")
	if root == "" {
		root = filepath.Join("..", "..", "secrets")
	}
	file, err := os.Open(filepath.Join(root, "betterleaks", "config", "betterleaks.toml"))
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var pure []*scan.Pattern
	var native []*hyperscan.Pattern
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "regex = '''") || !strings.HasSuffix(line, "'''") {
			continue
		}
		expression := strings.TrimSuffix(strings.TrimPrefix(line, "regex = '''"), "'''")
		id := len(pure)
		pure = append(pure, &scan.Pattern{Expression: expression, ID: uint(id), Flags: scan.SingleMatch | scan.AllowEmpty})
		if !includeNative {
			continue
		}
		pattern := hyperscan.NewPattern(expression, hyperscan.SingleMatch|hyperscan.AllowEmpty)
		pattern.Id = id
		if test, err := hyperscan.NewBlockDatabase(pattern); err != nil {
			pattern = hyperscan.NewPattern(expression, hyperscan.DotAll|hyperscan.SingleMatch|hyperscan.AllowEmpty|hyperscan.PrefilterMode)
			pattern.Id = id
		} else {
			_ = test.Close()
		}
		native = append(native, pattern)
	}
	if err := scanner.Err(); err != nil {
		tb.Fatal(err)
	}
	return pure, native
}

func benchmarkInputs(tb testing.TB) map[string][]byte {
	tb.Helper()
	root := os.Getenv("SECRETS_ROOT")
	if root == "" {
		root = filepath.Join("..", "..", "secrets")
	}
	inputs := make(map[string][]byte)
	for _, path := range []string{
		"main.go",
		"secrets",
		filepath.Join("betterleaks", "detect", "detect.go"),
		filepath.Join("betterleaks", "config", "betterleaks.toml"),
	} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			tb.Fatal(err)
		}
		inputs[filepath.Base(path)] = data
	}
	return inputs
}

type repositoryFile struct {
	name string
	data []byte
}

func benchmarkRepository(tb testing.TB) ([]repositoryFile, int64) {
	tb.Helper()
	root := os.Getenv("SECRETS_ROOT")
	if root == "" {
		root = filepath.Join("..", "..", "secrets")
	}
	output, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		tb.Fatal(err)
	}
	var files []repositoryFile
	var total int64
	for _, name := range bytes.Split(output, []byte{0}) {
		if len(name) == 0 {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, string(name)))
		if err != nil {
			tb.Fatal(err)
		}
		files = append(files, repositoryFile{name: string(name), data: data})
		total += int64(len(data))
	}
	return files, total
}

func TestRepositoryScanDiagnostics(t *testing.T) {
	if os.Getenv("SCAN_REPO_DIAGNOSTICS") == "" {
		t.Skip("set SCAN_REPO_DIAGNOSTICS=1")
	}
	patterns, _ := loadPatterns(t, false)
	db, err := scan.Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := benchmarkRepository(t)
	type timing struct {
		name     string
		bytes    int
		duration time.Duration
	}
	timings := make([]timing, 0, len(files))
	scratch := scan.NewScratch(db)
	for _, file := range files {
		if err := db.Scan(file.data, scratch, func(scan.Match) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range files {
		started := time.Now()
		if err := db.Scan(file.data, scratch, func(scan.Match) error { return nil }); err != nil {
			t.Fatal(err)
		}
		timings = append(timings, timing{name: file.name, bytes: len(file.data), duration: time.Since(started)})
	}
	sort.Slice(timings, func(left, right int) bool { return timings[left].duration > timings[right].duration })
	for _, result := range timings[:min(25, len(timings))] {
		t.Logf("%s bytes=%d duration=%s throughput=%.2f MB/s", result.name, result.bytes, result.duration, float64(result.bytes)/result.duration.Seconds()/1e6)
	}
}

func TestRepositoryMatchesVectorScan(t *testing.T) {
	purePatterns, nativePatterns := loadPatterns(t, true)
	pure, err := scan.Compile(purePatterns...)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := pure.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	pure, err = scan.UnmarshalDatabase(artifact)
	if err != nil {
		t.Fatal(err)
	}
	native, err := hyperscan.NewBlockDatabase(nativePatterns...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = native.Close() }()
	nativeScratch, err := hyperscan.NewScratch(native)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nativeScratch.Free() }()
	files, _ := benchmarkRepository(t)
	for _, file := range files {
		t.Run(file.name, func(t *testing.T) {
			pureMatches := make([]bool, len(purePatterns))
			err := pure.Scan(file.data, scan.NewScratch(pure), func(match scan.Match) error {
				pureMatches[match.ID] = true
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			nativeMatches := make([]bool, len(nativePatterns))
			err = native.Scan(file.data, nativeScratch, func(id uint, _, _ uint64, _ uint, _ interface{}) error {
				nativeMatches[id] = true
				return nil
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for id, matched := range pureMatches {
				if matched && !nativeMatches[id] {
					t.Errorf("pure-Go match %d was absent from VectorScan", id)
				}
				if nativePatterns[id].Flags&hyperscan.PrefilterMode == 0 && nativeMatches[id] && !matched {
					t.Errorf("VectorScan match %d was absent from pure Go: %s", id, purePatterns[id].Expression)
				}
			}
		})
	}
}

func BenchmarkPureGo(b *testing.B) {
	patterns, _ := loadPatterns(b, false)
	db, err := scan.Compile(patterns...)
	if err != nil {
		b.Fatal(err)
	}
	for name, data := range benchmarkInputs(b) {
		b.Run(name, func(b *testing.B) {
			scratch := scan.NewScratch(db)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				if err := db.Scan(data, scratch, func(scan.Match) error { return nil }); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVectorScan(b *testing.B) {
	_, patterns := loadPatterns(b, true)
	db, err := hyperscan.NewBlockDatabase(patterns...)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for name, data := range benchmarkInputs(b) {
		b.Run(name, func(b *testing.B) {
			scratch, err := hyperscan.NewScratch(db)
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = scratch.Free() }()
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				if err := db.Scan(data, scratch, func(uint, uint64, uint64, uint, interface{}) error { return nil }, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPureGoRepository(b *testing.B) {
	patterns, _ := loadPatterns(b, false)
	db, err := scan.Compile(patterns...)
	if err != nil {
		b.Fatal(err)
	}
	files, total := benchmarkRepository(b)
	scratch := scan.NewScratch(db)
	for _, file := range files {
		if err := db.Scan(file.data, scratch, func(scan.Match) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(total)
	b.ReportAllocs()
	for b.Loop() {
		for _, file := range files {
			if err := db.Scan(file.data, scratch, func(scan.Match) error { return nil }); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkVectorScanRepository(b *testing.B) {
	_, patterns := loadPatterns(b, true)
	db, err := hyperscan.NewBlockDatabase(patterns...)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	scratch, err := hyperscan.NewScratch(db)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = scratch.Free() }()
	files, total := benchmarkRepository(b)
	for _, file := range files {
		if err := db.Scan(file.data, scratch, func(uint, uint64, uint64, uint, interface{}) error { return nil }, nil); err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(total)
	b.ReportAllocs()
	for b.Loop() {
		for _, file := range files {
			if err := db.Scan(file.data, scratch, func(uint, uint64, uint64, uint, interface{}) error { return nil }, nil); err != nil {
				b.Fatal(err)
			}
		}
	}
}
