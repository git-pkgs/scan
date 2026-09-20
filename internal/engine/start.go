package engine

import (
	"bytes"
	"regexp/syntax"
	"unicode"
)

func expressionByteMask(re *syntax.Regexp) byteMask {
	var mask byteMask
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r <= 255 {
				mask.add(byte(r))
			}
			if re.Flags&syntax.FoldCase != 0 {
				for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
					if folded <= 255 {
						mask.add(byte(folded))
					}
				}
			}
		}
	case syntax.OpCharClass:
		for i := 0; i < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= min(255, re.Rune[i+1]); r++ {
				mask.add(byte(r))
			}
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		for value := 0; value < 256; value++ {
			if re.Op == syntax.OpAnyChar || value != '\n' {
				mask.add(byte(value))
			}
		}
	default:
		for _, child := range re.Sub {
			childMask := expressionByteMask(child)
			for word := range mask {
				mask[word] |= childMask[word]
			}
		}
	}
	return mask
}

func atomStartConstraint(atoms []atom) startConstraint {
	var mask byteMask
	skip := 0
	for _, candidate := range atoms {
		if candidate.prefixMax >= 0 {
			continue
		}
		for word := range mask {
			mask[word] |= candidate.prefixMask[word]
		}
		if candidate.prefixSkip < 0 || candidate.prefixSkip > 255 {
			return startConstraint{}
		}
		skip = max(skip, candidate.prefixSkip)
	}
	if mask.count() == 0 || mask.count() == 256 {
		return startConstraint{}
	}
	return startConstraint{kind: startWithinClass, mask: mask, value: byte(skip)}
}

func maskStartConstraint(atoms []maskAtom) startConstraint {
	prefixes := make([]atom, len(atoms))
	for i, candidate := range atoms {
		prefixes[i] = atom{prefixMax: candidate.prefixMax, prefixMask: candidate.prefixMask, prefixSkip: candidate.prefixSkip}
	}
	return atomStartConstraint(prefixes)
}

type startConstraintKind uint8

const (
	startUnbounded startConstraintKind = iota
	startAfterByte
	startWithinClass
)

type startConstraint struct {
	kind  startConstraintKind
	value byte // Delimiter for startAfterByte; tail distance for startWithinClass.
	mask  byteMask
}

func leadingStartConstraint(re *syntax.Regexp, byteMode bool) startConstraint {
	if !byteMode {
		return startConstraint{}
	}
	parts := leadingParts(re)
	if len(parts) == 0 {
		return startConstraint{}
	}
	if mask, ok := leadingPlusMask(parts[0]); ok {
		return startConstraint{kind: startWithinClass, mask: mask}
	}
	if len(parts) < 2 || parts[0].Op != syntax.OpLiteral || len(parts[0].Rune) != 1 || parts[0].Rune[0] > 255 {
		return startConstraint{}
	}
	mask, ok := leadingPlusMask(parts[1])
	if !ok || mask.contains(byte(parts[0].Rune[0])) {
		return startConstraint{}
	}
	return startConstraint{kind: startAfterByte, value: byte(parts[0].Rune[0])}
}

func leadingParts(re *syntax.Regexp) []*syntax.Regexp {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpConcat {
		return []*syntax.Regexp{re}
	}
	var parts []*syntax.Regexp
	for _, child := range re.Sub {
		for child.Op == syntax.OpCapture {
			child = child.Sub[0]
		}
		switch child.Op {
		case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpBeginText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
			continue
		case syntax.OpConcat:
			parts = append(parts, leadingParts(child)...)
		default:
			parts = append(parts, child)
		}
		if len(parts) >= 2 {
			break
		}
	}
	return parts
}

func leadingPlusMask(re *syntax.Regexp) (byteMask, bool) {
	if re.Op != syntax.OpPlus {
		return byteMask{}, false
	}
	masks, ok := fixedMasks(re.Sub[0], true)
	if !ok || len(masks) != 1 || len(masks[0]) != 1 {
		return byteMask{}, false
	}
	return masks[0][0], true
}

func (constraint startConstraint) bounds(data []byte, atomStart, startMax int) (int, int, bool) {
	switch constraint.kind {
	case startAfterByte:
		end := min(len(data), atomStart+1)
		start := bytes.LastIndexByte(data[:end], constraint.value)
		return start, start, start >= 0 && start <= startMax
	case startWithinClass:
		// The bounded tail may contain bytes outside the unbounded prefix class.
		start := max(0, min(atomStart, len(data))-int(constraint.value))
		for start > 0 && constraint.mask.contains(data[start-1]) {
			start--
		}
		return start, startMax, start <= startMax
	default:
		return 0, 0, false
	}
}
