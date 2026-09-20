package engine

import (
	"math/bits"
	"regexp/syntax"
	"unicode"
)

const maxMaskLength = 16
const maxFixedMaskBuild = 1024

type byteMask [4]uint64

func (m *byteMask) add(value byte) {
	m[value>>6] |= uint64(1) << (value & 63)
}

func (m byteMask) contains(value byte) bool {
	return m[value>>6]&(uint64(1)<<(value&63)) != 0
}

func (m byteMask) count() int {
	return bits.OnesCount64(m[0]) + bits.OnesCount64(m[1]) + bits.OnesCount64(m[2]) + bits.OnesCount64(m[3])
}

type maskAtom struct {
	masks      []byteMask
	prefixMin  int
	prefixMax  int
	prefixMask byteMask
	prefixSkip int
}

func requiredMaskAtoms(expression string, flags Flags) ([]maskAtom, bool) {
	re, err := parseExpression(expression, flags)
	if err != nil {
		return nil, false
	}
	atoms, ok := maskAtomsFor(re.Simplify(), !flags.has(UTF8))
	if !ok || len(atoms) == 0 || len(atoms) > maxTriggerAlternatives {
		return nil, false
	}
	for index := range atoms {
		atoms[index] = trimMaskAtom(atoms[index])
		if len(atoms[index].masks) < 2 {
			return nil, false
		}
		first, second, _ := bestMaskPair(atoms[index].masks)
		if first.count()*second.count() > 4096 {
			return nil, false
		}
	}
	return atoms, true
}

func maskAtomsFor(re *syntax.Regexp, byteMode bool) ([]maskAtom, bool) {
	if fixed, ok := fixedMasks(re, byteMode); ok {
		atoms := make([]maskAtom, len(fixed))
		for index := range fixed {
			atoms[index].masks = fixed[index]
		}
		return atoms, true
	}
	switch re.Op {
	case syntax.OpCapture:
		return maskAtomsFor(re.Sub[0], byteMode)
	case syntax.OpConcat:
		var best []maskAtom
		prefixMins := make([]int, len(re.Sub))
		prefixMaxes := make([]int, len(re.Sub))
		prefixMasks := make([]byteMask, len(re.Sub))
		prefixSkips := make([]int, len(re.Sub))
		prefixMin, prefixMax := 0, 0
		var prefixMask, prefixBoundary byteMask
		prefixSkip := 0
		for childIndex, child := range re.Sub {
			prefixMins[childIndex] = prefixMin
			prefixMaxes[childIndex] = prefixMax
			prefixMasks[childIndex] = prefixBoundary
			prefixSkips[childIndex] = prefixSkip
			candidate, ok := maskAtomsFor(child, byteMode)
			if ok {
				for index := range candidate {
					if candidate[index].prefixMax >= 0 {
						candidate[index].prefixMask = prefixBoundary
						candidate[index].prefixSkip = addWidth(prefixSkip, candidate[index].prefixMax)
					} else {
						for word := range prefixMask {
							candidate[index].prefixMask[word] |= prefixMask[word]
						}
					}
					candidate[index].prefixMin = addWidth(candidate[index].prefixMin, prefixMin)
					candidate[index].prefixMax = addWidth(candidate[index].prefixMax, prefixMax)
				}
				if betterMaskAtoms(candidate, best) {
					best = candidate
				}
			}
			childMin, childMax := asciiWidth(child)
			prefixMin = addWidth(prefixMin, childMin)
			prefixMax = addWidth(prefixMax, childMax)
			childMask := expressionByteMask(child)
			for word := range prefixMask {
				prefixMask[word] |= childMask[word]
			}
			if childMax < 0 {
				prefixBoundary, prefixSkip = prefixMask, 0
			} else {
				prefixSkip = addWidth(prefixSkip, childMax)
			}
		}
		for start := range re.Sub {
			sequences := [][]byteMask{{}}
			for end := start; end < len(re.Sub); end++ {
				fixed, ok := fixedMasks(re.Sub[end], byteMode)
				if !ok || len(sequences)*len(fixed) > maxTriggerAlternatives {
					break
				}
				sequences = combineMaskSequences(sequences, fixed)
				candidate := make([]maskAtom, len(sequences))
				for index := range sequences {
					candidate[index] = maskAtom{
						masks: sequences[index], prefixMin: prefixMins[start], prefixMax: prefixMaxes[start],
						prefixMask: prefixMasks[start], prefixSkip: prefixSkips[start],
					}
				}
				if betterMaskAtoms(candidate, best) {
					best = candidate
				}
			}
		}
		return best, len(best) > 0
	case syntax.OpAlternate:
		var combined []maskAtom
		for _, child := range re.Sub {
			candidate, ok := maskAtomsFor(child, byteMode)
			if !ok || len(combined)+len(candidate) > maxTriggerAlternatives {
				return nil, false
			}
			combined = append(combined, candidate...)
		}
		return combined, len(combined) > 0
	case syntax.OpPlus:
		return maskAtomsFor(re.Sub[0], byteMode)
	case syntax.OpRepeat:
		if re.Min > 0 {
			if fixed, ok := fixedMasks(re.Sub[0], byteMode); ok {
				result := make([]maskAtom, len(fixed))
				for index, sequence := range fixed {
					for range re.Min {
						result[index].masks = append(result[index].masks, sequence...)
					}
				}
				return result, true
			}
			return maskAtomsFor(re.Sub[0], byteMode)
		}
	}
	return nil, false
}

func combineMaskSequences(prefixes, suffixes [][]byteMask) [][]byteMask {
	result := make([][]byteMask, 0, len(prefixes)*len(suffixes))
	for _, prefix := range prefixes {
		for _, suffix := range suffixes {
			sequence := make([]byteMask, 0, len(prefix)+len(suffix))
			sequence = append(sequence, prefix...)
			sequence = append(sequence, suffix...)
			result = append(result, sequence)
		}
	}
	return result
}

func fixedMasks(re *syntax.Regexp, byteMode bool) ([][]byteMask, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return [][]byteMask{{}}, true
	case syntax.OpLiteral:
		sequence := make([]byteMask, len(re.Rune))
		for index, value := range re.Rune {
			maximum := rune(127)
			if byteMode {
				maximum = 255
			}
			if value < 0 || value > maximum {
				return nil, false
			}
			sequence[index].add(byte(value))
			if re.Flags&syntax.FoldCase != 0 {
				for folded := unicode.SimpleFold(value); folded != value; folded = unicode.SimpleFold(folded) {
					if folded >= 0 && folded <= maximum {
						sequence[index].add(byte(folded))
					}
				}
			}
		}
		return [][]byteMask{sequence}, true
	case syntax.OpCharClass:
		var mask byteMask
		for index := 0; index < len(re.Rune); index += 2 {
			first, last := re.Rune[index], re.Rune[index+1]
			if byteMode {
				first = max(first, 0)
				last = min(last, 255)
				if first > last {
					continue
				}
			} else if first < 0 || last > 127 {
				return nil, false
			}
			for value := first; value <= last; value++ {
				mask.add(byte(value))
			}
		}
		if mask.count() == 0 {
			return nil, false
		}
		return [][]byteMask{{mask}}, true
	case syntax.OpCapture:
		return fixedMasks(re.Sub[0], byteMode)
	case syntax.OpConcat:
		result := [][]byteMask{{}}
		for _, child := range re.Sub {
			alternatives, ok := fixedMasks(child, byteMode)
			if !ok || len(result)*len(alternatives) > maxTriggerAlternatives {
				return nil, false
			}
			var combined [][]byteMask
			for _, prefix := range result {
				for _, suffix := range alternatives {
					sequence := make([]byteMask, 0, len(prefix)+len(suffix))
					sequence = append(sequence, prefix...)
					sequence = append(sequence, suffix...)
					combined = append(combined, sequence)
				}
			}
			result = combined
		}
		return result, true
	case syntax.OpAlternate:
		var result [][]byteMask
		for _, child := range re.Sub {
			alternatives, ok := fixedMasks(child, byteMode)
			if !ok || len(result)+len(alternatives) > maxTriggerAlternatives {
				return nil, false
			}
			result = append(result, alternatives...)
		}
		return result, true
	case syntax.OpRepeat:
		if re.Min != re.Max || re.Min > maxFixedMaskBuild {
			return nil, false
		}
		alternatives, ok := fixedMasks(re.Sub[0], byteMode)
		if !ok || len(alternatives) != 1 {
			return nil, false
		}
		sequence := make([]byteMask, 0, len(alternatives[0])*re.Min)
		for range re.Min {
			sequence = append(sequence, alternatives[0]...)
		}
		return [][]byteMask{sequence}, true
	}
	return nil, false
}

func betterMaskAtoms(candidate, current []maskAtom) bool {
	if len(candidate) == 0 {
		return false
	}
	if len(current) == 0 {
		return true
	}
	candidateCost, candidateLength := maskAtomScore(candidate)
	currentCost, currentLength := maskAtomScore(current)
	candidateUsable := candidateLength >= 2
	currentUsable := currentLength >= 2
	if candidateUsable != currentUsable {
		return candidateUsable
	}
	if candidateCost != currentCost {
		return candidateCost < currentCost
	}
	return candidateLength > currentLength
}

func maskAtomScore(atoms []maskAtom) (int, int) {
	worstCost := 0
	shortest := int(^uint(0) >> 1)
	for _, atom := range atoms {
		trimmed := trimMaskAtom(atom)
		if len(trimmed.masks) < 2 {
			worstCost = int(^uint(0) >> 1)
		} else {
			first, second, _ := bestMaskPair(trimmed.masks)
			worstCost = max(worstCost, first.count()*second.count())
		}
		shortest = min(shortest, len(trimmed.masks))
	}
	return worstCost, shortest
}

func trimMaskAtom(atom maskAtom) maskAtom {
	if len(atom.masks) <= maxMaskLength {
		return atom
	}
	bestStart, bestCost := 0, int(^uint(0)>>1)
	for start := 0; start+maxMaskLength <= len(atom.masks); start++ {
		first, second, _ := bestMaskPair(atom.masks[start : start+maxMaskLength])
		cost := first.count() * second.count()
		if cost <= bestCost {
			bestStart, bestCost = start, cost
		}
	}
	atom.masks = atom.masks[bestStart : bestStart+maxMaskLength]
	atom.prefixMin = addWidth(atom.prefixMin, bestStart)
	atom.prefixMax = addWidth(atom.prefixMax, bestStart)
	atom.prefixSkip = addWidth(atom.prefixSkip, bestStart)
	return atom
}

func bestMaskPair(masks []byteMask) (byteMask, byteMask, int) {
	bestEnd, bestCost := 1, int(^uint(0)>>1)
	for end := 1; end < len(masks); end++ {
		cost := masks[end-1].count() * masks[end].count()
		if cost < bestCost {
			bestEnd, bestCost = end, cost
		}
	}
	return masks[bestEnd-1], masks[bestEnd], bestEnd
}
