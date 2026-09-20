package engine

import (
	"encoding/binary"
	"math/bits"
	"regexp/syntax"
)

const (
	maxDFAStates      = 512
	maxDFAProgram     = 2048
	maxDFARejectBytes = 256
	dfaMinRepeat      = 4
	dfaMaxRepeat      = 8
	dfaWordBits       = 64
	dfaWordBytes      = 8
	dfaAccept         = 1
	dfaDead           = 2
)

type rejectDFA struct {
	classes [256]uint8
	stride  int
	next    []uint16
	search  []uint16
}

type dfaState struct {
	bits      []uint64
	searching bool
}

type dfaBuilder struct {
	prog     *syntax.Prog
	masks    []byteMask
	closures [][]uint64
	initial  []uint64
	states   []dfaState
	ids      map[string]uint16
	matchPC  int
	limit    int
}

func compileRejectDFA(expression *syntax.Regexp, flags Flags) *rejectDFA {
	return compileRejectDFAWithLimit(expression, flags, maxDFAStates)
}

func compileRejectDFAWithLimit(expression *syntax.Regexp, flags Flags, limit int) *rejectDFA {
	if flags.has(UTF8) {
		return nil
	}
	prog, err := syntax.Compile(dfaExpression(expression).Simplify())
	if err != nil || len(prog.Inst) > maxDFAProgram {
		return nil
	}
	b := dfaBuilder{prog: prog, masks: compileByteMasks(prog), ids: make(map[string]uint16), limit: limit}
	words := (len(prog.Inst) + dfaWordBits - 1) / dfaWordBits
	b.closures = make([][]uint64, len(prog.Inst))
	for pc := range prog.Inst {
		if prog.Inst[pc].Op == syntax.InstMatch {
			b.matchPC = pc
		}
		b.closures[pc] = dfaClosure(prog, uint32(pc), words)
	}
	b.initial = b.closures[prog.Start]
	if b.initial[b.matchPC/dfaWordBits]&(uint64(1)<<(b.matchPC%dfaWordBits)) != 0 {
		return nil
	}
	// State one accepts. Assertions are checked by the reporting NFA.
	b.states = []dfaState{{bits: make([]uint64, words), searching: true}, {}, {bits: make([]uint64, words)}}
	b.ids[dfaStateKey(b.states[0].bits)+"s"] = 0
	b.ids[dfaStateKey(b.states[dfaDead].bits)+"a"] = dfaDead
	classes, alphabet := dfaAlphabet(b.masks, words)
	dfa := &rejectDFA{classes: classes, stride: len(alphabet)}
	initialTargets := make([][]uint64, len(alphabet))
	for class, value := range alphabet {
		initialTargets[class] = b.advance(b.initial, value)
	}
	for state := 0; state < len(b.states); state++ {
		dfa.next = append(dfa.next, make([]uint16, len(alphabet))...)
		dfa.search = append(dfa.search, make([]uint16, len(alphabet))...)
		if state == dfaAccept {
			continue
		}
		active := b.states[state]
		for class, value := range alphabet {
			target := b.advance(active.bits, value)
			id, ok := b.intern(target, false)
			if !ok {
				return nil
			}
			dfa.next[state*dfa.stride+class] = id
			if !active.searching {
				continue
			}
			searchTarget := append([]uint64(nil), target...)
			for word, successors := range initialTargets[class] {
				searchTarget[word] |= successors
			}
			id, ok = b.intern(searchTarget, true)
			if !ok {
				return nil
			}
			dfa.search[state*dfa.stride+class] = id
		}
	}
	return dfa
}

func dfaAlphabet(masks []byteMask, words int) ([256]uint8, []byte) {
	var classes [256]uint8
	var alphabet []byte
	classIDs := make(map[string]uint8)
	for value := range classes {
		signature := make([]uint64, words)
		for pc, mask := range masks {
			if mask.contains(byte(value)) {
				signature[pc/dfaWordBits] |= uint64(1) << (pc % dfaWordBits)
			}
		}
		key := dfaStateKey(signature)
		id, exists := classIDs[key]
		if !exists {
			id = uint8(len(alphabet))
			classIDs[key] = id
			alphabet = append(alphabet, byte(value))
		}
		classes[value] = id
	}
	return classes, alphabet
}

func (b *dfaBuilder) advance(active []uint64, value byte) []uint64 {
	target := make([]uint64, len(active))
	for word, activeBits := range active {
		for activeBits != 0 {
			pc := word*dfaWordBits + bits.TrailingZeros64(activeBits)
			activeBits &= activeBits - 1
			if !b.masks[pc].contains(value) {
				continue
			}
			for i, successors := range b.closures[b.prog.Inst[pc].Out] {
				target[i] |= successors
			}
		}
	}
	return target
}

func dfaExpression(expression *syntax.Regexp) *syntax.Regexp {
	copy := *expression
	copy.Sub = make([]*syntax.Regexp, len(expression.Sub))
	for i, child := range expression.Sub {
		copy.Sub[i] = dfaExpression(child)
	}
	if copy.Op == syntax.OpRepeat {
		copy.Min = min(copy.Min, dfaMinRepeat)
		if copy.Max > dfaMaxRepeat {
			copy.Max = -1
		}
	}
	return &copy
}

func (b *dfaBuilder) intern(state []uint64, searching bool) (uint16, bool) {
	if state[b.matchPC/dfaWordBits]&(uint64(1)<<(b.matchPC%dfaWordBits)) != 0 {
		return dfaAccept, true
	}
	key := dfaStateKey(state)
	if searching {
		key += "s"
	} else {
		key += "a"
	}
	if id, ok := b.ids[key]; ok {
		return id, true
	}
	if len(b.states) >= b.limit {
		return 0, false
	}
	id := uint16(len(b.states))
	b.states = append(b.states, dfaState{bits: state, searching: searching})
	b.ids[key] = id
	return id, true
}

func dfaStateKey(state []uint64) string {
	key := make([]byte, len(state)*dfaWordBytes)
	for i, word := range state {
		binary.LittleEndian.PutUint64(key[i*dfaWordBytes:], word)
	}
	return string(key)
}

func dfaClosure(prog *syntax.Prog, start uint32, words int) []uint64 {
	result := make([]uint64, words)
	visited := make([]bool, len(prog.Inst))
	stack := []uint32{start}
	for len(stack) != 0 {
		pc := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[pc] {
			continue
		}
		visited[pc] = true
		inst := &prog.Inst[pc]
		switch inst.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			stack = append(stack, inst.Out, inst.Arg)
		case syntax.InstNop, syntax.InstCapture, syntax.InstEmptyWidth:
			stack = append(stack, inst.Out)
		case syntax.InstFail:
		default:
			result[pc/dfaWordBits] |= uint64(1) << (pc % dfaWordBits)
		}
	}
	return result
}

func (dfa *rejectDFA) possible(data []byte, start, end, startMin, startMax int) bool {
	state := uint16(0)
	limit := min(end, max(start, startMin)+maxDFARejectBytes)
	for position := max(start, startMin); position <= limit; position++ {
		if state == dfaAccept {
			return true
		}
		if state == dfaDead {
			return false
		}
		if position == limit {
			return limit < end
		}
		index := int(state)*dfa.stride + int(dfa.classes[data[position]])
		if position <= startMax {
			state = dfa.search[index]
		} else {
			state = dfa.next[index]
		}
	}
	return false
}
