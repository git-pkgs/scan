package engine

import "regexp/syntax"

func skipNFALoops(data []byte, position, end int, seeds []uint32, loops []*[256]bool) int {
	for _, pc := range seeds {
		if loops[pc] == nil {
			return position
		}
	}
	for position < end {
		for _, pc := range seeds {
			if !loops[pc][data[position]] {
				return position
			}
		}
		position++
	}
	return position
}

func compileNFALoops(p *compiledPattern, tables map[byteMask]*[256]bool) {
	if p.source.Flags.has(UTF8) {
		return
	}
	for pc := range p.prog.Inst {
		mask := nfaLoopMask(p, uint32(pc))
		if mask == (byteMask{}) {
			continue
		}
		if p.loops == nil {
			p.loops = make([]*[256]bool, len(p.prog.Inst))
		}
		table := tables[mask]
		if table == nil {
			table = new([256]bool)
			for b := range table {
				table[b] = mask.contains(byte(b))
			}
			tables[mask] = table
		}
		p.loops[pc] = table
	}
}

func nfaLoopMask(p *compiledPattern, pc uint32) byteMask {
	var stay, leave byteMask
	for _, terminal := range p.epsilon[p.epsilonAt[pc]:p.epsilonAt[pc+1]] {
		inst := &p.prog.Inst[terminal]
		if inst.Op == syntax.InstMatch || inst.Op == syntax.InstEmptyWidth {
			return byteMask{}
		}
		for word, mask := range p.byteMasks[terminal] {
			if inst.Out == pc {
				stay[word] |= mask
			} else {
				leave[word] |= mask
			}
		}
	}
	for word := range stay {
		stay[word] &^= leave[word]
	}
	return stay
}
