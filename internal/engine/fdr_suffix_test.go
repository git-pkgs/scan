package engine

func compileLiteralSuffixGroups(groups [][]trigger) literalHashMatcher {
	return compileLiteralChosenGroups(groups, func(text []byte) (uint32, int) {
		end := len(text) - 1
		return uint32(lowerASCII(text[end-2]))<<16 | uint32(lowerASCII(text[end-1]))<<8 | uint32(lowerASCII(text[end])), end
	})
}

func compileLiteralChosenGroups(groups [][]trigger, choose func([]byte) (uint32, int)) literalHashMatcher {
	var heads [1 << 16]uint32
	entries := make([]triggerEntry, 0, len(groups))
	matcher := literalHashMatcher{
		buckets: make([]literalBucket, 0, len(groups)),
	}
	for groupID, triggers := range groups {
		fragment, pairEnd := choose(triggers[0].text)
		start := uint32(len(matcher.triggers))
		for _, candidate := range triggers {
			candidate.fragment = fragment
			candidate.pairEnd = pairEnd
			matcher.triggers = append(matcher.triggers, candidate)
		}
		checkAt, checkByte, checkFold := literalCheckByte(triggers[0].text, pairEnd, triggers[0].caseless)
		matcher.groups = append(matcher.groups, literalGroup{
			text: triggers[0].text, fragment: fragment, pairEnd: pairEnd, caseless: triggers[0].caseless,
			start: start, end: uint32(len(matcher.triggers)),
			checkAt: checkAt, checkByte: checkByte, checkFold: checkFold,
		})
		key := literalHash(fragment)
		entries = append(entries, triggerEntry{trigger: uint32(groupID), next: heads[key]})
		heads[key] = uint32(len(entries))
	}
	for key, head := range heads {
		matcher.offsets[key] = uint32(len(matcher.buckets))
		if head != 0 {
			matcher.present[key>>6] |= uint64(1) << (key & 63)
		}
		for entry := head; entry != 0; entry = entries[entry-1].next {
			group := entries[entry-1].trigger
			matcher.buckets = append(matcher.buckets, literalBucket{fragment: matcher.groups[group].fragment, group: group})
		}
	}
	matcher.offsets[1<<16] = uint32(len(matcher.buckets))
	return matcher
}
