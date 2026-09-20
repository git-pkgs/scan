package engine

import (
	"regexp/syntax"
	"unicode/utf8"
)

const maxPrecomputedClosureInput = 256 * 1024

type contextClosures struct {
	terminals []uint32
	offsets   [65]uint32
}

func compileStartClosures(prog *syntax.Prog) *contextClosures {
	closures := new(contextClosures)
	scratch := newNFAScratch(len(prog.Inst))
	for context := 0; context < 64; context++ {
		closures.offsets[context] = uint32(len(closures.terminals))
		terminals := scratch.dynamicClosure(prog, nil, nil, syntax.EmptyOp(context), uint32(prog.Start), 0, true)
		closures.terminals = append(closures.terminals, terminals...)
	}
	closures.offsets[64] = uint32(len(closures.terminals))
	return closures
}

type nfaScratch struct {
	generation uint32
	marks      []uint32
	starts     []int
	current    []uint32
	seedPC     []uint32
	seedStart  []int
	nextPC     []uint32
	nextStart  []int
	stackPC    []uint32
	stackStart []int
}

func newNFAScratch(size int) nfaScratch {
	return nfaScratch{
		marks:  make([]uint32, size),
		starts: make([]int, size),
	}
}

func compileByteMasks(prog *syntax.Prog) []byteMask {
	masks := make([]byteMask, len(prog.Inst))
	for pc := range prog.Inst {
		instruction := &prog.Inst[pc]
		switch instruction.Op {
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			for value := 0; value < 256; value++ {
				if instruction.MatchRune(rune(value)) {
					masks[pc].add(byte(value))
				}
			}
		}
	}
	return masks
}

func compileEpsilonClosures(prog *syntax.Prog) ([]uint32, []uint32) {
	var closures []uint32
	offsets := make([]uint32, len(prog.Inst)+1)
	marks := make([]uint32, len(prog.Inst))
	var generation uint32
	stack := make([]uint32, 0, len(prog.Inst))
	for start := range prog.Inst {
		offsets[start] = uint32(len(closures))
		generation++
		stack = append(stack[:0], uint32(start))
		for len(stack) > 0 {
			last := len(stack) - 1
			pc := stack[last]
			stack = stack[:last]
			if int(pc) >= len(prog.Inst) || marks[pc] == generation {
				continue
			}
			marks[pc] = generation
			instruction := &prog.Inst[pc]
			switch instruction.Op {
			case syntax.InstAlt, syntax.InstAltMatch:
				stack = append(stack, instruction.Out, instruction.Arg)
			case syntax.InstCapture, syntax.InstNop:
				stack = append(stack, instruction.Out)
			default:
				closures = append(closures, pc)
			}
		}
	}
	offsets[len(prog.Inst)] = uint32(len(closures))
	return closures, offsets
}

func scanNFA(data []byte, start, end, startMin, startMax int, pattern uint32, compiled *compiledPattern, scratch *Scratch, handler MatchHandler) error {
	if !compiled.source.Flags.has(UTF8) {
		return scanByteNFA(data, start, end, startMin, startMax, pattern, compiled, scratch, handler)
	}
	return scanUTF8NFA(data, start, end, startMin, startMax, pattern, compiled, scratch, handler)
}

func scanByteNFA(data []byte, start, end, startMin, startMax int, pattern uint32, compiled *compiledPattern, scratch *Scratch, handler MatchHandler) error {
	nfa := &scratch.nfa
	currentSeeds := nfa.seedPC[:0]
	currentStarts := nfa.seedStart[:0]
	loops := compiled.loops
	previous := -1
	if start > 0 {
		previous = int(data[start-1])
	}
	for position := start; position <= end; position++ {
		if loops != nil && position > startMax && len(currentSeeds) == 1 {
			if table := loops[currentSeeds[0]]; table != nil {
				for position < end && table[data[position]] {
					position++
				}
				previous = int(data[position-1])
			}
		} else if loops != nil && position > startMax && len(currentSeeds) > 1 && startMin == startMax {
			// All seeds share a start, so merging reentries cannot change offsets.
			position = skipNFALoops(data, position, end, currentSeeds, loops)
			previous = int(data[position-1])
		}
		next := -1
		if position < len(data) {
			next = int(data[position])
		}
		context := emptyOpContextByte(previous, next)
		addStart := position >= startMin && position <= startMax
		nfa.current = nfa.closure(compiled, currentSeeds, currentStarts, context, uint32(compiled.prog.Start), position, addStart, len(data) <= maxPrecomputedClosureInput)
		if !addStart && len(nfa.current) == 0 {
			break
		}
		matchedFrom := -1
		for _, pc := range nfa.current {
			if compiled.prog.Inst[pc].Op == syntax.InstMatch {
				candidate := nfa.starts[pc]
				if matchedFrom < 0 || candidate < matchedFrom {
					matchedFrom = candidate
				}
			}
		}
		if matchedFrom >= 0 {
			nfa.seedPC = currentSeeds[:0]
			nfa.seedStart = currentStarts[:0]
			from := uint64(0)
			if compiled.source.Flags.has(SomLeftMost) {
				from = uint64(matchedFrom)
			}
			if err := handler(Match{ID: compiled.source.ID, From: from, To: uint64(position)}); err != nil {
				return err
			}
			scratch.reported[pattern] = scratch.generation
			if compiled.source.Flags.has(SingleMatch) {
				return nil
			}
		}
		if position == end {
			break
		}
		nfa.nextPC = nfa.nextPC[:0]
		nfa.nextStart = nfa.nextStart[:0]
		for _, pc := range nfa.current {
			if compiled.byteMasks[pc].contains(byte(next)) {
				nfa.nextPC = append(nfa.nextPC, compiled.prog.Inst[pc].Out)
				nfa.nextStart = append(nfa.nextStart, nfa.starts[pc])
			}
		}
		currentSeeds, nfa.nextPC = nfa.nextPC, currentSeeds[:0]
		currentStarts, nfa.nextStart = nfa.nextStart, currentStarts[:0]
		previous = next
	}
	nfa.seedPC = currentSeeds[:0]
	nfa.seedStart = currentStarts[:0]
	return nil
}

func emptyOpContextByte(previous, next int) syntax.EmptyOp {
	var context syntax.EmptyOp
	if previous < 0 {
		context |= syntax.EmptyBeginLine | syntax.EmptyBeginText
	} else if previous == '\n' {
		context |= syntax.EmptyBeginLine
	}
	if next < 0 {
		context |= syntax.EmptyEndLine | syntax.EmptyEndText
	} else if next == '\n' {
		context |= syntax.EmptyEndLine
	}
	if isWordByte(previous) != isWordByte(next) {
		context |= syntax.EmptyWordBoundary
	} else {
		context |= syntax.EmptyNoWordBoundary
	}
	return context
}

func isWordByte(value int) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func scanUTF8NFA(data []byte, start, end, startMin, startMax int, pattern uint32, compiled *compiledPattern, scratch *Scratch, handler MatchHandler) error {
	for start < len(data) && start > 0 && data[start]&0xc0 == 0x80 {
		start++
	}
	for end < len(data) && data[end]&0xc0 == 0x80 {
		end++
	}
	nfa := &scratch.nfa
	currentSeeds := nfa.seedPC[:0]
	currentStarts := nfa.seedStart[:0]
	previous := rune(-1)
	if start > 0 {
		previous, _ = utf8.DecodeLastRune(data[:start])
	}
	for position := start; position <= end; {
		next := rune(-1)
		runeSize := 0
		if position < len(data) {
			next, runeSize = utf8.DecodeRune(data[position:])
		}
		context := syntax.EmptyOpContext(previous, next)
		addStart := position >= startMin && position <= startMax
		nfa.current = nfa.closure(compiled, currentSeeds, currentStarts, context, uint32(compiled.prog.Start), position, addStart, len(data) <= maxPrecomputedClosureInput)
		if !addStart && len(nfa.current) == 0 {
			break
		}
		matchedFrom := -1
		for _, pc := range nfa.current {
			if compiled.prog.Inst[pc].Op == syntax.InstMatch {
				candidate := nfa.starts[pc]
				if matchedFrom < 0 || candidate < matchedFrom {
					matchedFrom = candidate
				}
			}
		}
		if matchedFrom >= 0 {
			nfa.seedPC = currentSeeds[:0]
			nfa.seedStart = currentStarts[:0]
			from := uint64(0)
			if compiled.source.Flags.has(SomLeftMost) {
				from = uint64(matchedFrom)
			}
			if err := handler(Match{ID: compiled.source.ID, From: from, To: uint64(position)}); err != nil {
				return err
			}
			scratch.reported[pattern] = scratch.generation
			if compiled.source.Flags.has(SingleMatch) {
				return nil
			}
		}
		if position == end {
			break
		}
		nfa.nextPC = nfa.nextPC[:0]
		nfa.nextStart = nfa.nextStart[:0]
		for _, pc := range nfa.current {
			instruction := &compiled.prog.Inst[pc]
			if instruction.Op == syntax.InstRune || instruction.Op == syntax.InstRune1 ||
				instruction.Op == syntax.InstRuneAny || instruction.Op == syntax.InstRuneAnyNotNL {
				if instruction.MatchRune(next) {
					nfa.nextPC = append(nfa.nextPC, instruction.Out)
					nfa.nextStart = append(nfa.nextStart, nfa.starts[pc])
				}
			}
		}
		currentSeeds, nfa.nextPC = nfa.nextPC, currentSeeds[:0]
		currentStarts, nfa.nextStart = nfa.nextStart, currentStarts[:0]
		previous = next
		position += runeSize
	}
	nfa.seedPC = currentSeeds[:0]
	nfa.seedStart = currentStarts[:0]
	return nil
}

func (s *nfaScratch) closure(compiled *compiledPattern, seeds []uint32, seedStarts []int, context syntax.EmptyOp, startPC uint32, startPosition int, addStart, precomputed bool) []uint32 {
	if !precomputed {
		s.dynamicClosure(compiled.prog, seeds, seedStarts, context, startPC, startPosition, addStart && compiled.startClosures == nil)
		if addStart && compiled.startClosures != nil {
			s.appendStartClosure(compiled.startClosures, context, startPosition)
		}
		return s.current
	}
	s.generation++
	if s.generation == 0 {
		clear(s.marks)
		s.generation = 1
	}
	s.current = s.current[:0]
	s.stackPC = append(s.stackPC[:0], seeds...)
	s.stackStart = append(s.stackStart[:0], seedStarts...)
	if addStart && compiled.startClosures == nil {
		s.stackPC = append(s.stackPC, startPC)
		s.stackStart = append(s.stackStart, startPosition)
	}
	for len(s.stackPC) > 0 {
		last := len(s.stackPC) - 1
		pc := s.stackPC[last]
		matchStart := s.stackStart[last]
		s.stackPC = s.stackPC[:last]
		s.stackStart = s.stackStart[:last]
		if int(pc) >= len(compiled.prog.Inst) {
			continue
		}
		for _, terminal := range compiled.epsilon[compiled.epsilonAt[pc]:compiled.epsilonAt[pc+1]] {
			if s.marks[terminal] == s.generation && s.starts[terminal] <= matchStart {
				continue
			}
			first := s.marks[terminal] != s.generation
			s.marks[terminal] = s.generation
			s.starts[terminal] = matchStart
			instruction := &compiled.prog.Inst[terminal]
			if instruction.Op == syntax.InstEmptyWidth {
				if syntax.EmptyOp(instruction.Arg)&^context == 0 {
					s.stackPC = append(s.stackPC, instruction.Out)
					s.stackStart = append(s.stackStart, matchStart)
				}
			} else if first {
				s.current = append(s.current, terminal)
			}
		}
	}
	if addStart && compiled.startClosures != nil {
		s.appendStartClosure(compiled.startClosures, context, startPosition)
	}
	return s.current
}

func (s *nfaScratch) appendStartClosure(closures *contextClosures, context syntax.EmptyOp, startPosition int) {
	for _, pc := range closures.terminals[closures.offsets[context]:closures.offsets[context+1]] {
		if s.marks[pc] == s.generation {
			continue
		}
		s.marks[pc] = s.generation
		s.starts[pc] = startPosition
		s.current = append(s.current, pc)
	}
}

func (s *nfaScratch) dynamicClosure(prog *syntax.Prog, seeds []uint32, seedStarts []int, context syntax.EmptyOp, startPC uint32, startPosition int, addStart bool) []uint32 {
	s.generation++
	if s.generation == 0 {
		clear(s.marks)
		s.generation = 1
	}
	s.current = s.current[:0]
	s.stackPC = append(s.stackPC[:0], seeds...)
	s.stackStart = append(s.stackStart[:0], seedStarts...)
	if addStart {
		s.stackPC = append(s.stackPC, startPC)
		s.stackStart = append(s.stackStart, startPosition)
	}
	for len(s.stackPC) > 0 {
		last := len(s.stackPC) - 1
		pc := s.stackPC[last]
		matchStart := s.stackStart[last]
		s.stackPC = s.stackPC[:last]
		s.stackStart = s.stackStart[:last]
		if int(pc) >= len(prog.Inst) || s.marks[pc] == s.generation && s.starts[pc] <= matchStart {
			continue
		}
		first := s.marks[pc] != s.generation
		s.marks[pc] = s.generation
		s.starts[pc] = matchStart
		instruction := &prog.Inst[pc]
		switch instruction.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			s.stackPC = append(s.stackPC, instruction.Out, instruction.Arg)
			s.stackStart = append(s.stackStart, matchStart, matchStart)
		case syntax.InstCapture, syntax.InstNop:
			s.stackPC = append(s.stackPC, instruction.Out)
			s.stackStart = append(s.stackStart, matchStart)
		case syntax.InstEmptyWidth:
			if syntax.EmptyOp(instruction.Arg)&^context == 0 {
				s.stackPC = append(s.stackPC, instruction.Out)
				s.stackStart = append(s.stackStart, matchStart)
			}
		default:
			if first {
				s.current = append(s.current, pc)
			}
		}
	}
	return s.current
}
