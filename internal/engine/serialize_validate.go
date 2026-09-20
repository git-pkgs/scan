package engine

import (
	"regexp/syntax"
	"unicode"
)

func validOffsets(offsets []uint32, length int) bool {
	if len(offsets) == 0 || offsets[0] != 0 || uint64(offsets[len(offsets)-1]) != uint64(length) {
		return false
	}
	for i := 1; i < len(offsets); i++ {
		if offsets[i] < offsets[i-1] {
			return false
		}
	}
	return true
}

func validIDs(ids []uint32, length int) bool {
	for _, id := range ids {
		if uint64(id) >= uint64(length) {
			return false
		}
	}
	return true
}

func validDatabase(db *Database) bool {
	if len(db.patterns) == 0 || !validIDs(db.always, len(db.patterns)) {
		return false
	}
	for i := range db.patterns {
		if !validCompiledPattern(&db.patterns[i]) {
			return false
		}
	}
	m := &db.matcher
	if !validOffsets(m.hashed.offsets[:], len(m.hashed.buckets)) || !validOffsets(m.hashPairs.offsets[:], len(m.hashPairs.triggerIDs)) || !validIDs(m.hashPairs.triggerIDs, len(m.hashPairs.triggers)) {
		return false
	}
	for _, bucket := range m.hashed.buckets {
		if uint64(bucket.group) >= uint64(len(m.hashed.groups)) {
			return false
		}
	}
	for _, t := range m.hashPairs.triggers {
		if len(t.text) != 0 && len(t.text) != 2 {
			return false
		}
	}
	for _, group := range m.hashed.groups {
		if len(group.text) < 3 || group.pairEnd < 2 || group.pairEnd >= len(group.text) || group.checkAt < 0 || group.checkAt >= len(group.text) || group.start >= group.end || uint64(group.end) > uint64(len(m.hashed.triggers)) {
			return false
		}
	}
	for _, triggers := range [][]trigger{m.hashed.triggers, m.hashPairs.triggers} {
		for _, t := range triggers {
			if uint64(t.pattern) >= uint64(len(db.patterns)) || !validPrefix(t.prefixMin, t.prefixMax) {
				return false
			}
			if len(t.masks) > 0 {
				if len(t.text) != 0 || t.pairEnd < 1 || t.pairEnd >= len(t.masks) {
					return false
				}
			} else if len(t.text) < 2 {
				return false
			}
		}
	}
	return true
}

func validPrefix(minimum, maximum int) bool {
	const limit = int(^uint(0)>>1) / 8
	return minimum >= 0 && minimum <= limit && (maximum == -1 || maximum >= minimum && maximum <= limit)
}

func validCompiledPattern(p *compiledPattern) bool {
	n := len(p.prog.Inst)
	if n == 0 || p.prog.Start < 0 || p.prog.Start >= n || p.prog.NumCap < 0 || p.source.Flags & ^Flags(255) != 0 || p.width < -1 || p.width > int(^uint(0)>>1)/8 || p.start.kind > startWithinClass {
		return false
	}
	if len(p.byteMasks) != n || len(p.epsilonAt) != n+1 || !validOffsets(p.epsilonAt, len(p.epsilon)) || !validIDs(p.epsilon, n) {
		return false
	}
	if p.startClosures != nil && (!validOffsets(p.startClosures.offsets[:], len(p.startClosures.terminals)) || !validIDs(p.startClosures.terminals, n)) {
		return false
	}
	if len(p.loops) != 0 && (len(p.loops) != n || p.source.Flags.has(UTF8)) {
		return false
	}
	if guard := p.literalGuard; guard != nil {
		if p.source.Flags.has(UTF8) || guard.newlines < 0 || guard.newlines > maxLiteralGuardNewlines || len(guard.literals) == 0 || len(guard.literals) > maxLiteralGuardAlternatives {
			return false
		}
		for _, literal := range guard.literals {
			if len(literal) < 2 || len(literal) > maxLiteralGuardBytes {
				return false
			}
		}
	}
	for _, inst := range p.prog.Inst {
		if !validInstruction(inst, n) {
			return false
		}
	}
	for pc, table := range p.loops {
		if table == nil {
			continue
		}
		mask := nfaLoopMask(p, uint32(pc))
		for b, yes := range table {
			if yes != mask.contains(byte(b)) {
				return false
			}
		}
	}
	for _, g := range p.guards {
		if g.length < 1 || g.length > int(^uint(0)>>1)/8 || !validPrefix(g.prefixMin, g.prefixMax) {
			return false
		}
		for b, yes := range g.lookup {
			if yes != g.mask.contains(byte(b)) {
				return false
			}
		}
	}
	return p.dfa == nil || validDFA(p.dfa)
}

func validInstruction(inst syntax.Inst, count int) bool {
	if uint64(inst.Out) >= uint64(count) {
		return false
	}
	switch inst.Op {
	case syntax.InstAlt, syntax.InstAltMatch:
		return uint64(inst.Arg) < uint64(count)
	case syntax.InstCapture, syntax.InstNop, syntax.InstMatch, syntax.InstFail:
		return true
	case syntax.InstEmptyWidth:
		return inst.Arg <= 63
	case syntax.InstRune, syntax.InstRune1:
		if len(inst.Rune) == 0 || inst.Op == syntax.InstRune1 && len(inst.Rune) != 1 || len(inst.Rune) > 1 && len(inst.Rune)%2 != 0 {
			return false
		}
		for i, r := range inst.Rune {
			if r < 0 || r > unicode.MaxRune || i > 0 && r < inst.Rune[i-1] {
				return false
			}
		}
		return inst.Arg & ^uint32(syntax.FoldCase) == 0
	case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
		return true
	default:
		return false
	}
}

func validDFA(d *rejectDFA) bool {
	if d.stride < 1 || d.stride > 256 || len(d.next) != len(d.search) || len(d.next)%d.stride != 0 {
		return false
	}
	states := len(d.next) / d.stride
	if states < 3 || states > 1<<16 {
		return false
	}
	for _, class := range d.classes {
		if int(class) >= d.stride {
			return false
		}
	}
	for _, table := range [][]uint16{d.next, d.search} {
		for _, state := range table {
			if int(state) >= states {
				return false
			}
		}
	}
	return true
}
