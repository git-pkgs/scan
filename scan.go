package scan

import "github.com/git-pkgs/scan/internal/engine"

// Flags change how an expression is compiled or reported.
type Flags = engine.Flags

const (
	Caseless    = engine.Caseless
	DotAll      = engine.DotAll
	MultiLine   = engine.MultiLine
	SingleMatch = engine.SingleMatch
	AllowEmpty  = engine.AllowEmpty
	UTF8        = engine.UTF8
	Prefilter   = engine.Prefilter
	SomLeftMost = engine.SomLeftMost
)

var (
	ErrInvalid        = engine.ErrInvalid
	ErrScanTerminated = engine.ErrScanTerminated
	ErrScratchInUse   = engine.ErrScratchInUse
)

// Pattern associates an expression and compile flags with an application ID.
type Pattern struct {
	Expression string
	Flags      Flags
	ID         uint
}

// Database is an immutable block-mode multi-pattern database.
type Database engine.Database

// CompileStats describes the routing decisions made while compiling a database.
type CompileStats = engine.CompileStats

// Match is reported for one expression occurrence.
type Match = engine.Match

// MatchHandler receives matches in engine order. Returning an error stops callbacks.
type MatchHandler = engine.MatchHandler

// Scratch contains mutable scan state. Concurrent scans need separate scratches.
type Scratch engine.Scratch

// NewPattern returns a pattern with the supplied expression and flags.
func NewPattern(expression string, flags Flags) *Pattern {
	return (*Pattern)(engine.NewPattern(expression, flags))
}

// Valid reports whether the pattern can be compiled.
func (p Pattern) Valid() bool {
	return engine.Pattern(p).Valid()
}

// Compile builds one block database from patterns.
// Patterns must be trusted; compilation does not enforce resource budgets.
func Compile(patterns ...*Pattern) (*Database, error) {
	inputs := make([]*engine.Pattern, len(patterns))
	for i, pattern := range patterns {
		inputs[i] = (*engine.Pattern)(pattern)
	}
	db, err := engine.Compile(inputs...)
	return (*Database)(db), err
}

// NewScratch allocates scan state for db.
func NewScratch(db *Database) *Scratch {
	return (*Scratch)(engine.NewScratch((*engine.Database)(db)))
}

// Clone returns independent scan state with the same capacity.
func (s *Scratch) Clone() *Scratch {
	return (*Scratch)((*engine.Scratch)(s).Clone())
}

// Scan searches data and reports matching end offsets in ascending order.
// Returning an error stops callbacks, after matching work has completed.
func (db *Database) Scan(data []byte, scratch *Scratch, handler MatchHandler) error {
	return (*engine.Database)(db).Scan(data, (*engine.Scratch)(scratch), handler)
}

// Match reports whether any expression matches data.
func (db *Database) Match(data []byte, scratch *Scratch) (bool, error) {
	return (*engine.Database)(db).Match(data, (*engine.Scratch)(scratch))
}

// Size returns the approximate bytes held by the database.
func (db *Database) Size() int {
	return (*engine.Database)(db).Size()
}

// Stats returns counts useful when tuning a pattern set.
func (db *Database) Stats() CompileStats {
	return (*engine.Database)(db).Stats()
}

// Marshal encodes the compiled database for storage or go:embed.
func (db *Database) Marshal() ([]byte, error) {
	return (*engine.Database)(db).Marshal()
}

// UnmarshalDatabase loads compiled tables produced by a trusted compiler.
func UnmarshalDatabase(data []byte) (*Database, error) {
	db, err := engine.UnmarshalDatabase(data)
	return (*Database)(db), err
}
