package engine

import "regexp/syntax"

// Pattern associates an expression and compile flags with an application ID.
type Pattern struct {
	Expression string
	Flags      Flags
	ID         uint
}

// NewPattern returns a pattern with the supplied expression and flags.
func NewPattern(expression string, flags Flags) *Pattern {
	return &Pattern{Expression: expression, Flags: flags}
}

// Valid reports whether the pattern can be compiled.
func (p Pattern) Valid() bool {
	_, err := parseExpression(p.Expression, p.Flags)
	return err == nil
}

func parseExpression(expression string, flags Flags) (*syntax.Regexp, error) {
	var prefix string
	if flags.has(Caseless) {
		prefix += "i"
	}
	if flags.has(DotAll) {
		prefix += "s"
	}
	if flags.has(MultiLine) {
		prefix += "m"
	}
	if prefix != "" {
		expression = "(?" + prefix + ":" + expression + ")"
	}
	return syntax.Parse(expression, syntax.Perl)
}
