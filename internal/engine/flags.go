package engine

// Flags change how an expression is compiled or reported.
type Flags uint32

const (
	Caseless Flags = 1 << iota
	DotAll
	MultiLine
	SingleMatch
	AllowEmpty
	UTF8
	Prefilter
	SomLeftMost
)

func (f Flags) has(flag Flags) bool {
	return f&flag != 0
}
