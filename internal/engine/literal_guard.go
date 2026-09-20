package engine

import (
	"bytes"
	"regexp/syntax"
)

const (
	maxLiteralGuardBytes        = 2048
	maxLiteralGuardNewlines     = 16
	maxLiteralGuardAlternatives = 4
)

type literalGuard struct {
	literals [][]byte
	newlines int
	before   byteMask
}

func compileLiteralGuard(re *syntax.Regexp, flags Flags) *literalGuard {
	if flags.has(UTF8) {
		return nil
	}
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpConcat {
		return nil
	}
	width, newlines := 0, 0
	var best *literalGuard
	for i, part := range re.Sub {
		if width < 0 && newlines >= 0 && newlines <= maxLiteralGuardNewlines {
			tail := &syntax.Regexp{Op: syntax.OpConcat, Sub: re.Sub[i:]}
			prefixes, _, ok := literalPrefixes(tail)
			if ok && len(prefixes) > 0 && len(prefixes) <= maxLiteralGuardAlternatives {
				guard := &literalGuard{newlines: newlines}
				if i > 0 {
					minimum, maximum := asciiWidth(re.Sub[i-1])
					if minimum == 1 && maximum == 1 {
						guard.before = expressionByteMask(re.Sub[i-1])
					}
				}
				for _, prefix := range prefixes {
					if len(prefix.text) < 2 || len(prefix.text) > maxLiteralGuardBytes || prefix.caseless {
						guard = nil
						break
					}
					guard.literals = append(guard.literals, prefix.text)
				}
				if guard != nil && (best == nil || len(guard.literals[0]) > len(best.literals[0])) {
					guard.literals = compactGuardLiterals(guard.literals)
					best = guard
				}
			}
		}
		_, partWidth := asciiWidth(part)
		width = addWidth(width, partWidth)
		newlines = addWidth(newlines, maximumNewlines(part))
	}
	return best
}

func compactGuardLiterals(literals [][]byte) [][]byte {
	var result [][]byte
	for i, literal := range literals {
		redundant := false
		for j, other := range literals {
			if i != j && (len(other) < len(literal) || j < i) && bytes.HasPrefix(literal, other) {
				redundant = true
				break
			}
		}
		if !redundant {
			result = append(result, literal)
		}
	}
	return result
}

func maximumNewlines(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		count := 0
		for _, r := range re.Rune {
			if r == '\n' {
				count++
			}
		}
		return count
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		if expressionByteMask(re).contains('\n') {
			return 1
		}
		return 0
	case syntax.OpCapture, syntax.OpQuest:
		return maximumNewlines(re.Sub[0])
	case syntax.OpConcat:
		count := 0
		for _, child := range re.Sub {
			count = addWidth(count, maximumNewlines(child))
		}
		return count
	case syntax.OpAlternate:
		count := 0
		for _, child := range re.Sub {
			n := maximumNewlines(child)
			if n < 0 {
				return -1
			}
			count = max(count, n)
		}
		return count
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		count := maximumNewlines(re.Sub[0])
		if count == 0 {
			return 0
		}
		if re.Op == syntax.OpRepeat && re.Max >= 0 {
			return multiplyWidth(count, re.Max)
		}
		return -1
	}
	return 0
}

func (g *literalGuard) possible(data []byte, startMin, startMax, end int) bool {
	limit := min(end, startMin+maxLiteralGuardBytes)
	if startMax > limit {
		return true
	}
	position := startMax
	budgetBound := true
	for count := 0; count <= g.newlines; count++ {
		next := bytes.IndexByte(data[position:limit], '\n')
		if next < 0 {
			break
		}
		position += next + 1
		if count == g.newlines {
			budgetBound = false
		}
	}
	if !budgetBound {
		limit = position - 1
	}
	for _, literal := range g.literals {
		// The newline bound limits the literal's start, not its end.
		searchEnd := min(end, limit+len(literal))
		for first := startMin; first < searchEnd; {
			offset := bytes.Index(data[first:searchEnd], literal)
			if offset < 0 {
				break
			}
			at := first + offset
			if g.before == (byteMask{}) || at > 0 && g.before.contains(data[at-1]) {
				return true
			}
			first = at + 1
		}
	}
	return budgetBound && limit < end
}
