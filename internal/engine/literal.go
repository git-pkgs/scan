package engine

import (
	"bytes"
	"encoding/binary"
	"math"
	"regexp/syntax"
	"sort"
	"unicode"
	"unicode/utf8"
)

const maxTriggerAlternatives = 64

var asciiLower = func() [256]byte {
	var table [256]byte
	for value := range table {
		table[value] = byte(value)
	}
	for value := byte('A'); value <= 'Z'; value++ {
		table[value] = value + ('a' - 'A')
	}
	return table
}()

type trigger struct {
	text      []byte
	masks     []byteMask
	fragment  uint32
	pairEnd   int
	pattern   uint32
	caseless  bool
	prefixMin int
	prefixMax int
}

type literalMatcher struct {
	hashed    literalHashMatcher
	hashPairs triggerTable
	fdr       *fdrMatcher
}

type literalHashMatcher struct {
	offsets  [1<<16 + 1]uint32
	present  [1 << 10]uint64
	buckets  []literalBucket
	triggers []trigger
	groups   []literalGroup
}

type literalBucket struct {
	fragment uint32
	group    uint32
}

type literalGroup struct {
	text      []byte
	pairEnd   int
	checkAt   int
	fragment  uint32
	start     uint32
	end       uint32
	checkByte byte
	checkFold byte
	caseless  bool
}

type triggerTable struct {
	offsets    [1<<16 + 1]uint32
	present    [1 << 10]uint64
	triggerIDs []uint32
	triggers   []trigger
}

type triggerTableBuilder struct {
	heads    [1 << 16]uint32
	entries  []triggerEntry
	triggers []trigger
}

type triggerEntry struct {
	trigger uint32
	next    uint32
}

func newLiteralMatcher(triggers []trigger) literalMatcher {
	var hashed []trigger
	var hashPairs triggerTableBuilder
	for _, candidate := range triggers {
		switch {
		case len(candidate.masks) > 0:
			hashPairs.add(candidate)
		default:
			if len(candidate.text) < 3 {
				hashPairs.addLiteral(candidate)
			} else {
				hashed = append(hashed, candidate)
			}
		}
	}
	matcher := literalMatcher{
		hashed:    newLiteralHashMatcher(hashed),
		hashPairs: hashPairs.build(),
	}
	if len(matcher.hashed.groups) >= 64 {
		matcher.fdr = compileFDR(&matcher)
	}
	return matcher
}

func newLiteralHashMatcher(triggers []trigger) literalHashMatcher {
	type literalKey struct {
		text     string
		caseless bool
	}
	ids := make(map[literalKey]int)
	var groups [][]trigger
	for _, candidate := range triggers {
		key := literalKey{text: string(candidate.text), caseless: candidate.caseless}
		id, exists := ids[key]
		if !exists {
			id = len(groups)
			ids[key] = id
			groups = append(groups, nil)
		}
		groups[id] = append(groups[id], candidate)
	}
	return newLiteralHashGroups(groups)
}

func newLiteralHashGroups(groups [][]trigger) literalHashMatcher {
	frequencies := make(map[uint32]int)
	for _, group := range groups {
		var window uint32
		seen := make(map[uint32]bool)
		for offset, value := range group[0].text {
			window = window<<8&0xffffff | uint32(lowerASCII(value))
			if offset >= 2 && !seen[window] {
				frequencies[window]++
				seen[window] = true
			}
		}
	}
	for fragment, frequency := range frequencies {
		frequencies[fragment] = frequency * frequency
	}
	return compileLiteralHashGroups(groups, frequencies)
}

func compileLiteralHashGroups(groups [][]trigger, costs map[uint32]int) literalHashMatcher {
	var heads [1 << 16]uint32
	entries := make([]triggerEntry, 0, len(groups))
	matcher := literalHashMatcher{
		buckets: make([]literalBucket, 0, len(groups)),
	}
	for groupID, triggers := range groups {
		fragment, pairEnd := bestLiteralFragment(triggers[0].text, costs, len(groups) >= 64)
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

func literalCheckByte(text []byte, fragmentEnd int, caseless bool) (int, byte, byte) {
	best, score := 0, int(^uint(0)>>1)
	for position, value := range text {
		if len(text) > 3 && position >= fragmentEnd-2 && position <= fragmentEnd {
			continue
		}
		if weight := literalByteWeight(lowerASCII(value)); weight < score {
			best, score = position, weight
		}
	}
	value, fold := text[best], byte(0)
	if caseless && lowerASCII(value) >= 'a' && lowerASCII(value) <= 'z' {
		value = lowerASCII(value)
		fold = 'a' - 'A'
	}
	return best, value, fold
}

func bestLiteralFragment(text []byte, costs map[uint32]int, fdr bool) (uint32, int) {
	bestScore := math.Inf(1)
	var best uint32
	bestEnd := 2
	for start := 0; start+3 <= len(text); start++ {
		first := lowerASCII(text[start])
		second := lowerASCII(text[start+1])
		third := lowerASCII(text[start+2])
		fragment := uint32(first)<<16 | uint32(second)<<8 | uint32(third)
		score := float64(literalByteWeight(first)) * float64(literalByteWeight(second)) * float64(literalByteWeight(third)) * float64(max(1, costs[fragment]))
		if fdr {
			// FDR can reject on up to eight bytes preceding the fragment end.
			score /= float64(min(start+3, 8))
		}
		if score < bestScore {
			best = fragment
			bestEnd = start + 2
			bestScore = score
		}
	}
	return best, bestEnd
}

func literalByteWeight(value byte) int {
	switch value {
	case ' ':
		return 18
	case '\n', '\r', '\t':
		return 5
	case 'e', 't', 'a', 'o', 'i', 'n':
		return 12
	case 's', 'h', 'r', 'd', 'l', 'u':
		return 8
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return 4
	case '_', '-', '/', '.', ':', '=', '"', '\'':
		return 3
	default:
		return 1
	}
}

func literalHash(fragment uint32) uint16 {
	return uint16((fragment * 0x9e3779b1) >> 16)
}

func (t *triggerTableBuilder) add(candidate trigger) {
	length := len(candidate.masks)
	if length < 2 {
		return
	}
	id := uint32(len(t.triggers))
	t.triggers = append(t.triggers, candidate)
	first, second, pairEnd := bestMaskPair(candidate.masks)
	t.triggers[id].pairEnd = pairEnd
	for left := 0; left < 256; left++ {
		if !first.contains(byte(left)) {
			continue
		}
		for right := 0; right < 256; right++ {
			if second.contains(byte(right)) {
				t.addEntry(id, uint16(left)<<8|uint16(right))
			}
		}
	}
}

func (t *triggerTableBuilder) addLiteral(candidate trigger) {
	if len(candidate.text) != 2 {
		return
	}
	id := uint32(len(t.triggers))
	t.triggers = append(t.triggers, candidate)
	for left := 0; left < 256; left++ {
		if candidate.caseless {
			if lowerASCII(byte(left)) != candidate.text[0] {
				continue
			}
		} else if byte(left) != candidate.text[0] {
			continue
		}
		for right := 0; right < 256; right++ {
			if candidate.caseless {
				if lowerASCII(byte(right)) != candidate.text[1] {
					continue
				}
			} else if byte(right) != candidate.text[1] {
				continue
			}
			t.addEntry(id, uint16(left)<<8|uint16(right))
		}
	}
}

func (t *triggerTableBuilder) addEntry(triggerID uint32, key uint16) {
	t.entries = append(t.entries, triggerEntry{trigger: triggerID, next: t.heads[key]})
	t.heads[key] = uint32(len(t.entries))
}

func (t *triggerTableBuilder) build() triggerTable {
	result := triggerTable{
		triggerIDs: make([]uint32, 0, len(t.entries)),
		triggers:   t.triggers,
	}
	for key, head := range t.heads {
		result.offsets[key] = uint32(len(result.triggerIDs))
		if head != 0 {
			result.present[key>>6] |= uint64(1) << (key & 63)
		}
		for entry := head; entry != 0; entry = t.entries[entry-1].next {
			result.triggerIDs = append(result.triggerIDs, t.entries[entry-1].trigger)
		}
	}
	result.offsets[1<<16] = uint32(len(result.triggerIDs))
	return result
}

func (m *literalMatcher) scan(data []byte, scratch *Scratch) {
	if m.fdr != nil {
		m.scanFDR(data, scratch)
		return
	}
	m.scanHash(data, scratch)
}

func (m *literalMatcher) scanHash(data []byte, scratch *Scratch) {
	if len(data) == 0 {
		return
	}
	hashed := &m.hashed
	masked := &m.hashPairs
	var window uint32
	previous := data[0]
	window = uint32(lowerASCII(previous))
	offset := 1
	if len(data) > 1 {
		current := data[1]
		window = window<<8&0xffffff | uint32(lowerASCII(current))
		key := uint16(previous)<<8 | uint16(current)
		if masked.present[key>>6]&(uint64(1)<<(key&63)) != 0 {
			masked.confirm(data, 1, key, scratch)
		}
		previous = current
		offset = 2
	}
	for ; offset+8 <= len(data); offset += 8 {
		raw := binary.BigEndian.Uint64(data[offset:])
		folded := foldASCIIWord(raw)
		previousWindow := window
		window = window<<8&0xffffff | uint32(folded>>56)
		key := literalHash(window)
		if hashed.present[key>>6]&(uint64(1)<<(key&63)) != 0 {
			hashed.confirm(data, offset, window, key, scratch)
		}
		pairKey := uint16(previous)<<8 | uint16(raw>>56)
		if masked.present[pairKey>>6]&(uint64(1)<<(pairKey&63)) != 0 {
			masked.confirm(data, offset, pairKey, scratch)
		}

		window = previousWindow<<16&0xffffff | uint32(folded>>48)
		key = literalHash(window)
		if hashed.present[key>>6]&(uint64(1)<<(key&63)) != 0 {
			hashed.confirm(data, offset+1, window, key, scratch)
		}
		pairKey = uint16(raw >> 48)
		if masked.present[pairKey>>6]&(uint64(1)<<(pairKey&63)) != 0 {
			masked.confirm(data, offset+1, pairKey, scratch)
		}

		window = uint32(folded>>40) & 0xffffff
		key = literalHash(window)
		if hashed.present[key>>6]&(uint64(1)<<(key&63)) != 0 {
			hashed.confirm(data, offset+2, window, key, scratch)
		}
		pairKey = uint16(raw >> 40)
		if masked.present[pairKey>>6]&(uint64(1)<<(pairKey&63)) != 0 {
			masked.confirm(data, offset+2, pairKey, scratch)
		}

		window = uint32(folded>>32) & 0xffffff
		key = literalHash(window)
		if hashed.present[key>>6]&(uint64(1)<<(key&63)) != 0 {
			hashed.confirm(data, offset+3, window, key, scratch)
		}
		pairKey = uint16(raw >> 32)
		if masked.present[pairKey>>6]&(uint64(1)<<(pairKey&63)) != 0 {
			masked.confirm(data, offset+3, pairKey, scratch)
		}

		window = uint32(folded>>24) & 0xffffff
		key = literalHash(window)
		if hashed.present[key>>6]&(uint64(1)<<(key&63)) != 0 {
			hashed.confirm(data, offset+4, window, key, scratch)
		}
		pairKey = uint16(raw >> 24)
		if masked.present[pairKey>>6]&(uint64(1)<<(pairKey&63)) != 0 {
			masked.confirm(data, offset+4, pairKey, scratch)
		}

		window = uint32(folded>>16) & 0xffffff
		key = literalHash(window)
		if hashed.present[key>>6]&(uint64(1)<<(key&63)) != 0 {
			hashed.confirm(data, offset+5, window, key, scratch)
		}
		pairKey = uint16(raw >> 16)
		if masked.present[pairKey>>6]&(uint64(1)<<(pairKey&63)) != 0 {
			masked.confirm(data, offset+5, pairKey, scratch)
		}

		window = uint32(folded>>8) & 0xffffff
		key = literalHash(window)
		if hashed.present[key>>6]&(uint64(1)<<(key&63)) != 0 {
			hashed.confirm(data, offset+6, window, key, scratch)
		}
		pairKey = uint16(raw >> 8)
		if masked.present[pairKey>>6]&(uint64(1)<<(pairKey&63)) != 0 {
			masked.confirm(data, offset+6, pairKey, scratch)
		}

		window = uint32(folded) & 0xffffff
		key = literalHash(window)
		if hashed.present[key>>6]&(uint64(1)<<(key&63)) != 0 {
			hashed.confirm(data, offset+7, window, key, scratch)
		}
		pairKey = uint16(raw)
		if masked.present[pairKey>>6]&(uint64(1)<<(pairKey&63)) != 0 {
			masked.confirm(data, offset+7, pairKey, scratch)
		}
		previous = byte(raw)
	}
	for ; offset < len(data); offset++ {
		current := data[offset]
		window = window<<8&0xffffff | uint32(lowerASCII(current))
		key := literalHash(window)
		if hashed.present[key>>6]&(uint64(1)<<(key&63)) != 0 {
			hashed.confirm(data, offset, window, key, scratch)
		}
		pairKey := uint16(previous)<<8 | uint16(current)
		if masked.present[pairKey>>6]&(uint64(1)<<(pairKey&63)) != 0 {
			masked.confirm(data, offset, pairKey, scratch)
		}
		previous = current
	}
}

func foldASCIIWord(value uint64) uint64 {
	// Seven-bit lanes prevent carries between bytes during the range checks.
	low := value & 0x7f7f7f7f7f7f7f7f
	upper := (low + 0x3f3f3f3f3f3f3f3f) & ^(low + 0x2525252525252525) & ^value & 0x8080808080808080
	return value | upper>>2
}

func (m *literalHashMatcher) confirm(data []byte, offset int, window uint32, key uint16, scratch *Scratch) {
	for _, bucket := range m.buckets[m.offsets[key]:m.offsets[int(key)+1]] {
		if bucket.fragment != window {
			continue
		}
		group := &m.groups[bucket.group]
		start := offset - group.pairEnd
		end := start + len(group.text)
		if start < 0 || end > len(data) {
			continue
		}
		if data[start+group.checkAt]|group.checkFold != group.checkByte {
			continue
		}
		if group.caseless {
			if !equalFoldASCII(data[start:end], group.text) {
				continue
			}
		} else if !bytes.Equal(data[start:end], group.text) {
			continue
		}
		for triggerID := group.start; triggerID < group.end; triggerID++ {
			scratch.addHit(&m.triggers[triggerID], start, end)
		}
	}
}

func (t *triggerTable) confirm(data []byte, offset int, key uint16, scratch *Scratch) {
	for _, triggerID := range t.triggerIDs[t.offsets[key]:t.offsets[int(key)+1]] {
		candidate := &t.triggers[triggerID]
		if len(candidate.text) > 0 {
			start := offset + 1 - len(candidate.text)
			if candidate.caseless || bytes.Equal(data[start:offset+1], candidate.text) {
				scratch.addHit(candidate, start, offset+1)
			}
			continue
		}
		start := offset - candidate.pairEnd
		if start >= 0 && start+len(candidate.masks) <= len(data) && candidate.matches(data[start:start+len(candidate.masks)]) {
			scratch.addHit(candidate, start, offset+1)
		}
	}
}

func equalFoldASCII(data, folded []byte) bool {
	for index, value := range data {
		if lowerASCII(value) != folded[index] {
			return false
		}
	}
	return true
}

func (t *trigger) matches(data []byte) bool {
	for index, mask := range t.masks {
		if !mask.contains(data[index]) {
			return false
		}
	}
	return true
}

func lowerASCII(b byte) byte {
	return asciiLower[b]
}

type atom struct {
	text       []byte
	caseless   bool
	prefixMin  int
	prefixMax  int
	prefixMask byteMask
	prefixSkip int
}

func requiredAtoms(expression string, reFlags Flags) ([]atom, bool) {
	re, err := parseExpression(expression, reFlags)
	if err != nil {
		return nil, false
	}
	re = re.Simplify()
	atoms, ok := atomsFor(re)
	if prefixes, _, prefixOK := literalPrefixes(re); prefixOK && betterAtoms(prefixes, atoms) {
		atoms, ok = prefixes, true
	}
	if !ok || len(atoms) == 0 || len(atoms) > maxTriggerAlternatives {
		return nil, false
	}
	for i := range atoms {
		if len(atoms[i].text) < 2 {
			return nil, false
		}
		if atoms[i].caseless {
			for j := range atoms[i].text {
				atoms[i].text[j] = lowerASCII(atoms[i].text[j])
			}
		}
	}
	sort.Slice(atoms, func(i, j int) bool {
		if atoms[i].caseless != atoms[j].caseless {
			return !atoms[i].caseless
		}
		return bytes.Compare(atoms[i].text, atoms[j].text) < 0
	})
	return compactAtoms(atoms), true
}

func literalPrefixes(re *syntax.Regexp) ([]atom, bool, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []atom{{}}, true, true
	case syntax.OpLiteral:
		text, ascii := literalBytes(re.Rune)
		if !ascii {
			return nil, false, false
		}
		return []atom{{text: text, caseless: re.Flags&syntax.FoldCase != 0}}, true, true
	case syntax.OpCapture:
		return literalPrefixes(re.Sub[0])
	case syntax.OpConcat:
		result := []atom{{}}
		for _, child := range re.Sub {
			prefixes, complete, ok := literalPrefixes(child)
			if !ok || len(result)*len(prefixes) > maxTriggerAlternatives {
				return result, false, len(result) > 0
			}
			combined, ok := combineLiteralPrefixes(result, prefixes)
			if !ok {
				return result, false, len(result) > 0
			}
			result = combined
			if !complete {
				return result, false, true
			}
		}
		return result, true, true
	case syntax.OpAlternate:
		var result []atom
		complete := true
		for _, child := range re.Sub {
			prefixes, childComplete, ok := literalPrefixes(child)
			if !ok || len(result)+len(prefixes) > maxTriggerAlternatives {
				return nil, false, false
			}
			result = append(result, prefixes...)
			complete = complete && childComplete
		}
		return result, complete, len(result) > 0
	case syntax.OpRepeat:
		if re.Min == 0 {
			return []atom{{}}, false, true
		}
		prefixes, complete, ok := literalPrefixes(re.Sub[0])
		if !ok || !complete {
			return prefixes, false, ok
		}
		result := []atom{{}}
		for range re.Min {
			if len(result)*len(prefixes) > maxTriggerAlternatives {
				return nil, false, false
			}
			result, ok = combineLiteralPrefixes(result, prefixes)
			if !ok {
				return nil, false, false
			}
		}
		return result, re.Min == re.Max, true
	case syntax.OpPlus:
		prefixes, _, ok := literalPrefixes(re.Sub[0])
		return prefixes, false, ok
	case syntax.OpQuest, syntax.OpStar, syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return []atom{{}}, false, true
	}
	return nil, false, false
}

func combineLiteralPrefixes(left, right []atom) ([]atom, bool) {
	result := make([]atom, 0, len(left)*len(right))
	for _, prefix := range left {
		for _, suffix := range right {
			if len(prefix.text) > 0 && len(suffix.text) > 0 && prefix.caseless != suffix.caseless {
				return nil, false
			}
			combined := atom{caseless: prefix.caseless || suffix.caseless}
			combined.text = make([]byte, 0, len(prefix.text)+len(suffix.text))
			combined.text = append(combined.text, prefix.text...)
			combined.text = append(combined.text, suffix.text...)
			result = append(result, combined)
		}
	}
	return result, true
}

func atomsFor(re *syntax.Regexp) ([]atom, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		text, ascii := literalBytes(re.Rune)
		if !ascii || len(text) == 0 {
			return nil, false
		}
		return []atom{{text: text, caseless: re.Flags&syntax.FoldCase != 0}}, true
	case syntax.OpCapture:
		return atomsFor(re.Sub[0])
	case syntax.OpConcat:
		var best []atom
		prefixMin, prefixMax := 0, 0
		var prefixMask byteMask
		var prefixBoundary byteMask
		prefixSkip := 0
		for _, child := range re.Sub {
			candidate, ok := atomsFor(child)
			if ok {
				for i := range candidate {
					if candidate[i].prefixMax >= 0 {
						candidate[i].prefixMask = prefixBoundary
						candidate[i].prefixSkip = addWidth(prefixSkip, candidate[i].prefixMax)
					} else {
						for word := range prefixMask {
							candidate[i].prefixMask[word] |= prefixMask[word]
						}
					}
					candidate[i].prefixMin += prefixMin
					candidate[i].prefixMax = addWidth(candidate[i].prefixMax, prefixMax)
				}
			}
			if ok && betterAtoms(candidate, best) {
				best = candidate
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
		return best, len(best) > 0
	case syntax.OpAlternate:
		var combined []atom
		for _, child := range re.Sub {
			candidate, ok := atomsFor(child)
			if !ok || len(candidate) == 0 || len(combined)+len(candidate) > maxTriggerAlternatives {
				return nil, false
			}
			combined = append(combined, candidate...)
		}
		return combined, len(combined) > 0
	case syntax.OpPlus:
		return atomsFor(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return atomsFor(re.Sub[0])
		}
	}
	return nil, false
}

func literalBytes(runes []rune) ([]byte, bool) {
	result := make([]byte, 0, len(runes))
	for _, r := range runes {
		if r >= utf8.RuneSelf || r == unicode.ReplacementChar {
			return nil, false
		}
		result = append(result, byte(r))
	}
	return result, true
}

func betterAtoms(candidate, current []atom) bool {
	if len(candidate) == 0 {
		return false
	}
	if len(current) == 0 {
		return true
	}
	candidateMin := len(candidate[0].text)
	for _, value := range candidate[1:] {
		candidateMin = min(candidateMin, len(value.text))
	}
	currentMin := len(current[0].text)
	for _, value := range current[1:] {
		currentMin = min(currentMin, len(value.text))
	}
	candidateUsable := candidateMin >= 2
	currentUsable := currentMin >= 2
	if candidateUsable != currentUsable {
		return candidateUsable
	}
	candidateFinite := finiteAtomPrefixes(candidate)
	currentFinite := finiteAtomPrefixes(current)
	if candidateFinite != currentFinite {
		return candidateFinite
	}
	if candidateMin != currentMin {
		return candidateMin > currentMin
	}
	return len(candidate) < len(current)
}

func finiteAtomPrefixes(atoms []atom) bool {
	for _, candidate := range atoms {
		if candidate.prefixMax < 0 {
			return false
		}
	}
	return true
}

func compactAtoms(atoms []atom) []atom {
	result := atoms[:0]
	for _, candidate := range atoms {
		if len(result) > 0 && result[len(result)-1].caseless == candidate.caseless && bytes.Equal(result[len(result)-1].text, candidate.text) {
			for word := range candidate.prefixMask {
				result[len(result)-1].prefixMask[word] |= candidate.prefixMask[word]
			}
			if result[len(result)-1].prefixSkip < 0 || candidate.prefixSkip < 0 {
				result[len(result)-1].prefixSkip = -1
			} else {
				result[len(result)-1].prefixSkip = max(result[len(result)-1].prefixSkip, candidate.prefixSkip)
			}
			result[len(result)-1].prefixMin = min(result[len(result)-1].prefixMin, candidate.prefixMin)
			if result[len(result)-1].prefixMax < 0 || candidate.prefixMax < 0 {
				result[len(result)-1].prefixMax = -1
			} else {
				result[len(result)-1].prefixMax = max(result[len(result)-1].prefixMax, candidate.prefixMax)
			}
			continue
		}
		result = append(result, candidate)
	}
	return result
}

func asciiWidth(re *syntax.Regexp) (int, int) {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, 0
	case syntax.OpLiteral:
		return len(re.Rune), len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return 1, 1
	case syntax.OpCapture:
		return asciiWidth(re.Sub[0])
	case syntax.OpConcat:
		minimum, maximum := 0, 0
		for _, child := range re.Sub {
			childMin, childMax := asciiWidth(child)
			minimum = addWidth(minimum, childMin)
			maximum = addWidth(maximum, childMax)
		}
		return minimum, maximum
	case syntax.OpAlternate:
		minimum, maximum := -1, 0
		for _, child := range re.Sub {
			childMin, childMax := asciiWidth(child)
			if minimum < 0 || childMin < minimum {
				minimum = childMin
			}
			if maximum < 0 || childMax < 0 {
				maximum = -1
			} else {
				maximum = max(maximum, childMax)
			}
		}
		return max(0, minimum), maximum
	case syntax.OpQuest:
		_, maximum := asciiWidth(re.Sub[0])
		return 0, maximum
	case syntax.OpStar:
		_, maximum := asciiWidth(re.Sub[0])
		if maximum == 0 {
			return 0, 0
		}
		return 0, -1
	case syntax.OpPlus:
		minimum, maximum := asciiWidth(re.Sub[0])
		if maximum != 0 {
			maximum = -1
		}
		return minimum, maximum
	case syntax.OpRepeat:
		minimum, maximum := asciiWidth(re.Sub[0])
		minimum = multiplyWidth(minimum, re.Min)
		if re.Max < 0 {
			if maximum != 0 {
				maximum = -1
			}
		} else {
			maximum = multiplyWidth(maximum, re.Max)
		}
		return minimum, maximum
	}
	return 0, -1
}

func addWidth(left, right int) int {
	if left < 0 || right < 0 || left > int(^uint(0)>>1)-right {
		return -1
	}
	return left + right
}

func multiplyWidth(width, count int) int {
	if width < 0 || count < 0 || count != 0 && width > int(^uint(0)>>1)/count {
		return -1
	}
	return width * count
}
