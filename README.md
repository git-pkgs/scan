# scan

A Go library for matching many regular expressions against blocks of bytes. It compiles patterns into shared literal filters and regex automata, with Hyperscan and VectorScan as engine references and gohs as the API reference. There is no cgo, native library, or third-party module dependency.

The library is experimental. The API and compiled database format may change.

## Installation

Requires Go 1.26 or later.

```bash
go get github.com/git-pkgs/scan
```

## Usage

Compile a trusted pattern set once, then reuse the database and scratch space across inputs. Compilation has no CPU or memory budget; applications accepting untrusted rule configurations must impose their own limits.

```go
package main

import (
	"fmt"
	"log"

	"github.com/git-pkgs/scan"
)

func main() {
	db, err := scan.Compile(
		&scan.Pattern{Expression: `token=[a-z0-9]{8}`, ID: 1, Flags: scan.SingleMatch | scan.SomLeftMost},
		&scan.Pattern{Expression: `code=[0-9]{4}`, ID: 2, Flags: scan.SingleMatch | scan.SomLeftMost},
	)
	if err != nil {
		log.Fatal(err)
	}

	scratch := scan.NewScratch(db)
	err = db.Scan([]byte("token=abc12345 code=1234"), scratch, func(match scan.Match) error {
		fmt.Printf("%d %d:%d\n", match.ID, match.From, match.To)
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

This prints `1 0:14` and `2 15:24`. IDs come from the patterns; offsets are byte offsets, with an exclusive end.

Use `Match` when only a boolean result is needed:

```go
matched, err := db.Match(data, scratch)
```

Databases can be shared between goroutines. Each concurrent scan needs its own scratch space; `scratch.Clone()` creates an independent scratch for another worker. Passing `nil` instead of scratch allocates it internally; reusing scratch retains its buffers between calls and grows them when a larger database needs more space.

### Embed compiled patterns

`Marshal` serializes the compiled tables. A build-time generator can write them to a file:

```go
compiled, err := db.Marshal()
if err != nil {
	log.Fatal(err)
}
if err := os.WriteFile("patterns.scan", compiled, 0o644); err != nil {
	log.Fatal(err)
}
```

Embed that file in the application and load it once at startup:

```go
import (
	_ "embed"

	"github.com/git-pkgs/scan"
)

//go:embed patterns.scan
var compiledPatterns []byte

func loadPatterns() (*scan.Database, error) {
	return scan.UnmarshalDatabase(compiledPatterns)
}
```

Generate the file before running `go build`. Loading restores the compiled tables without parsing or recompiling expressions. Artifacts are versioned, so regenerate them when upgrading to an incompatible format. Only load artifacts produced by a trusted compiler; the checksum detects corruption but does not authenticate the contents.

## Matching behaviour

Patterns use Go's `regexp/syntax` parser. Look-around and backreferences are unsupported. Matching is byte-oriented by default; `UTF8` enables rune-oriented matching, while reported offsets remain byte offsets.

`Scan` reports matching end offsets in ascending order, including overlapping matches. It reports one event per pattern and end offset, without capture groups. `SomLeftMost` includes the earliest matching start in `From`; without it, `From` is zero. `SingleMatch` limits each pattern to one event per scan.

`Caseless`, `DotAll`, and `MultiLine` control case folding, whether dot matches newlines, and line anchors. Expressions that can match empty input require `AllowEmpty`. The `Prefilter` flag is reserved and currently does not relax matching semantics.

`Scan` collects and sorts events before invoking the handler. Returning an error stops further callbacks and returns that error, but does not avoid the matching work already done. `Match` avoids event collection and sorting and stops residual matching after its first match.

Only block scanning is supported. Each call treats its input as a separate block; matches do not span calls. There are no streaming or vectored scan APIs, and this package is not a drop-in replacement for gohs.

## Performance

A paired run on an Apple M1 Pro scanned a 38.7 MB repository corpus with 416 patterns in 44.9 to 45.0 ms with scan, versus 47.4 to 47.5 ms with VectorScan. Each backend had three 750 ms benchmark runs on one CPU. These are warmed block-scanner timings, excluding compilation, database loading, and Git I/O. Scan allocated zero bytes per warmed pass.

The corpus includes a 34 MB binary, where scan performs well. Individual source and config inputs still take roughly two to three times the native scanning time. The aggregate result does not imply a general speed advantage or end-to-end parity when scanning Git history.

## Testing

```bash
CGO_ENABLED=0 go test ./...
go test ./internal/engine -run '^$' -bench . -benchmem
go test ./internal/engine -run '^$' -fuzz '^FuzzSecretsScan$' -fuzztime=30s -parallel=1
```

Corpus tests, benchmarks, and the input fuzz target use the adjacent `../secrets` checkout, or the directory set by `SECRETS_ROOT`. They skip when the corpus is unavailable. Other tests run without that checkout.

The public API and examples are at the module root. Scanner implementation and its tests are in `internal/engine`. The separate `bench` module contains the native VectorScan comparisons and the `cmd/e2e` CLI comparison tool; its cgo dependency is excluded from the library module.

## License

[MIT](LICENSE). [fdr.go](internal/engine/fdr.go) and [teddy_diagnostic_test.go](internal/engine/teddy_diagnostic_test.go) contain code derived from Intel's Hyperscan under BSD-3-Clause. Their copyright and license notices are retained in those files.
