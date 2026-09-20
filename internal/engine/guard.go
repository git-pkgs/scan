package engine

import "regexp/syntax"

const minimumRunGuard = 8

type runGuard struct {
	mask      byteMask
	lookup    *[256]bool
	length    int
	prefixMin int
	prefixMax int
}

func requiredRunGuards(re *syntax.Regexp, byteMode bool) []runGuard {
	if !byteMode {
		return nil
	}
	guards, ok := runGuardsFor(re)
	if !ok {
		return nil
	}
	for _, guard := range guards {
		if guard.length < minimumRunGuard || guard.prefixMax < 0 {
			return nil
		}
	}
	return guards
}

func internRunGuardLookups(guards []runGuard, lookups map[byteMask]*[256]bool) {
	for index := range guards {
		lookup := lookups[guards[index].mask]
		if lookup == nil {
			lookup = new([256]bool)
			for value := 0; value < 256; value++ {
				lookup[value] = guards[index].mask.contains(byte(value))
			}
			lookups[guards[index].mask] = lookup
		}
		guards[index].lookup = lookup
	}
}

func runGuardsFor(re *syntax.Regexp) ([]runGuard, bool) {
	switch re.Op {
	case syntax.OpCapture:
		return runGuardsFor(re.Sub[0])
	case syntax.OpConcat:
		var best []runGuard
		prefixMin, prefixMax := 0, 0
		for _, child := range re.Sub {
			candidate, ok := runGuardsFor(child)
			if ok {
				for index := range candidate {
					candidate[index].prefixMin = addWidth(candidate[index].prefixMin, prefixMin)
					candidate[index].prefixMax = addWidth(candidate[index].prefixMax, prefixMax)
				}
				if betterRunGuards(candidate, best) {
					best = candidate
				}
			}
			childMin, childMax := asciiWidth(child)
			prefixMin = addWidth(prefixMin, childMin)
			prefixMax = addWidth(prefixMax, childMax)
		}
		return best, len(best) > 0
	case syntax.OpAlternate:
		var combined []runGuard
		for _, child := range re.Sub {
			candidate, ok := runGuardsFor(child)
			if !ok || len(combined)+len(candidate) > maxTriggerAlternatives {
				return nil, false
			}
			combined = append(combined, candidate...)
		}
		return combined, len(combined) > 0
	case syntax.OpRepeat:
		if re.Min < minimumRunGuard {
			return nil, false
		}
		masks, ok := fixedMasks(re.Sub[0], true)
		if !ok || len(masks) != 1 || len(masks[0]) != 1 {
			return nil, false
		}
		return []runGuard{{mask: masks[0][0], length: re.Min}}, true
	}
	return nil, false
}

func betterRunGuards(candidate, current []runGuard) bool {
	if len(candidate) == 0 {
		return false
	}
	if len(current) == 0 {
		return true
	}
	candidateLength := candidate[0].length
	for _, guard := range candidate[1:] {
		candidateLength = min(candidateLength, guard.length)
	}
	currentLength := current[0].length
	for _, guard := range current[1:] {
		currentLength = min(currentLength, guard.length)
	}
	if candidateLength != currentLength {
		return candidateLength > currentLength
	}
	return len(candidate) < len(current)
}

func matchRunGuards(data []byte, startMin, startMax, end int, guards []runGuard) bool {
	for index := range guards {
		guard := &guards[index]
		first := max(0, addWidth(startMin, guard.prefixMin))
		last := end - guard.length
		if guard.prefixMax >= 0 {
			last = min(last, addWidth(startMax, guard.prefixMax))
		}
		if first <= last && containsMaskedRun(data, first, last, guard) {
			return true
		}
	}
	return false
}

func containsMaskedRun(data []byte, first, last int, guard *runGuard) bool {
	limit := min(len(data), last+guard.length)
	for end := first + guard.length; end <= limit; {
		start := end - guard.length
		position := end - 1
		for position >= start && guard.lookup[data[position]] {
			position--
		}
		if position < start {
			return true
		}
		end = position + 1 + guard.length
	}
	return false
}
