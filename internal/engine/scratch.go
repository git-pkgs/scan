package engine

import "sync/atomic"

// Scratch contains mutable scan state. A caller needs one Scratch per
// concurrent scan. Scanning a larger database grows its buffers as needed.
type Scratch struct {
	inUse      atomic.Bool
	generation uint32
	marks      []uint32
	candidates []uint32
	hits       []literalHit
	hitHeads   []int32
	hitTails   []int32
	matches    []queuedMatch
	collectFor uint32
	reported   []uint32
	nfa        nfaScratch
}

type literalHit struct {
	pattern      uint32
	end          uint32
	atomStart    uint32
	startMin     uint32
	wideStartMin uint32
	startMax     uint32
	next         int32
	unbounded    bool
}

type queuedMatch struct {
	match   Match
	pattern uint32
}

// NewScratch allocates scan state for db.
func NewScratch(db *Database) *Scratch {
	return &Scratch{
		marks:    make([]uint32, len(db.patterns)),
		hitHeads: make([]int32, len(db.patterns)),
		hitTails: make([]int32, len(db.patterns)),
		reported: make([]uint32, len(db.patterns)),
		nfa:      newNFAScratch(db.maxProgram),
	}
}

// Clone returns independent scan state with the same capacity.
func (s *Scratch) Clone() *Scratch {
	return &Scratch{
		marks:    make([]uint32, len(s.marks)),
		hitHeads: make([]int32, len(s.hitHeads)),
		hitTails: make([]int32, len(s.hitTails)),
		reported: make([]uint32, len(s.reported)),
		nfa:      newNFAScratch(len(s.nfa.marks)),
	}
}

func (s *Scratch) prepare(patterns int) error {
	if !s.inUse.CompareAndSwap(false, true) {
		return ErrScratchInUse
	}
	if len(s.marks) < patterns {
		s.marks = make([]uint32, patterns)
		s.hitHeads = make([]int32, patterns)
		s.hitTails = make([]int32, patterns)
		s.reported = make([]uint32, patterns)
	}
	s.candidates = s.candidates[:0]
	s.hits = s.hits[:0]
	s.matches = s.matches[:0]
	s.generation++
	if s.generation == 0 {
		clear(s.marks)
		s.generation = 1
	}
	return nil
}

func (s *Scratch) release() {
	s.inUse.Store(false)
}

func (s *Scratch) addCandidate(pattern uint32) {
	if s.marks[pattern] == s.generation {
		return
	}
	s.marks[pattern] = s.generation
	s.candidates = append(s.candidates, pattern)
	s.hitHeads[pattern] = -1
	s.hitTails[pattern] = -1
}

func (s *Scratch) addHit(candidate *trigger, atomStart, end int) {
	startMax := atomStart - candidate.prefixMin
	if startMax < 0 {
		return
	}
	startMin := 0
	wideStartMin := 0
	if candidate.prefixMax >= 0 {
		startMin = max(0, atomStart-candidate.prefixMax)
		wideStartMin = max(0, atomStart-candidate.prefixMax*4)
	}
	s.addCandidate(candidate.pattern)
	hitIndex := int32(len(s.hits))
	s.hits = append(s.hits, literalHit{
		pattern: candidate.pattern, end: uint32(end), atomStart: uint32(atomStart),
		startMin: uint32(startMin), wideStartMin: uint32(wideStartMin), startMax: uint32(startMax),
		next: -1, unbounded: candidate.prefixMax < 0,
	})
	if tail := s.hitTails[candidate.pattern]; tail >= 0 {
		s.hits[tail].next = hitIndex
	} else {
		s.hitHeads[candidate.pattern] = hitIndex
	}
	s.hitTails[candidate.pattern] = hitIndex
}
