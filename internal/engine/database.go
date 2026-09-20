package engine

import (
	"encoding/binary"
	"fmt"
	"regexp/syntax"
	"slices"
	"unsafe"
)

// Match is reported for one expression occurrence.
type Match struct {
	ID    uint
	From  uint64
	To    uint64
	Flags uint
}

// MatchHandler receives matches in engine order. Returning an error stops the
// scan and returns that error.
type MatchHandler func(Match) error

type compiledPattern struct {
	source        Pattern
	prog          *syntax.Prog
	byteMasks     []byteMask
	epsilon       []uint32
	epsilonAt     []uint32
	startClosures *contextClosures
	loops         []*[256]bool
	guards        []runGuard
	literalGuard  *literalGuard
	dfa           *rejectDFA
	start         startConstraint
	width         int
}

// Database is an immutable block-mode multi-pattern database.
type Database struct {
	patterns   []compiledPattern
	matcher    literalMatcher
	always     []uint32
	size       int
	maxProgram int
}

// CompileStats describes the routing decisions made while compiling a database.
type CompileStats struct {
	Patterns          int
	Accelerated       int
	AlwaysRun         int
	Bounded           int
	SensitiveTriggers int
	CaselessTriggers  int
	MaskTriggers      int
	HashTriggers      int
	HashLiterals      int
	PairTriggers      int
	RunGuards         int
	GuardClasses      int
	DFAPatterns       int
	DFAStates         int
}

// Compile builds one block database from patterns.
// Patterns must be trusted; compilation does not enforce resource budgets.
func Compile(patterns ...*Pattern) (*Database, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("%w: no patterns", ErrInvalid)
	}
	db := &Database{patterns: make([]compiledPattern, 0, len(patterns))}
	var triggers []trigger
	guardLookups := make(map[byteMask]*[256]bool)
	for index, pattern := range patterns {
		if pattern == nil {
			return nil, fmt.Errorf("pattern %d: %w", index, ErrInvalid)
		}
		parsed, err := parseExpression(pattern.Expression, pattern.Flags)
		if err != nil {
			return nil, fmt.Errorf("pattern %d: %w", index, err)
		}
		if nullable(parsed) && !pattern.Flags.has(AllowEmpty) {
			return nil, fmt.Errorf("pattern %d matches empty input: %w", index, ErrInvalid)
		}
		prog, err := syntax.Compile(parsed.Simplify())
		if err != nil {
			return nil, fmt.Errorf("pattern %d: %w", index, err)
		}
		db.maxProgram = max(db.maxProgram, len(prog.Inst))
		epsilon, epsilonAt := compileEpsilonClosures(prog)
		guards := requiredRunGuards(parsed, !pattern.Flags.has(UTF8))
		internRunGuardLookups(guards, guardLookups)
		db.patterns = append(db.patterns, compiledPattern{
			source:        *pattern,
			prog:          prog,
			byteMasks:     compileByteMasks(prog),
			epsilon:       epsilon,
			epsilonAt:     epsilonAt,
			startClosures: compileStartClosures(prog),
			guards:        guards,
			start:         leadingStartConstraint(parsed, !pattern.Flags.has(UTF8)),
			width:         maximumWidth(parsed),
		})
		db.patterns[index].dfa = compileRejectDFA(parsed, pattern.Flags)
		if db.patterns[index].dfa == nil {
			db.patterns[index].literalGuard = compileLiteralGuard(parsed, pattern.Flags)
		}
		compileNFALoops(&db.patterns[index], guardLookups)
		atoms, accelerated := requiredAtoms(pattern.Expression, pattern.Flags)
		atomStart := atomStartConstraint(atoms)
		maskAtoms, maskAccelerated := requiredMaskAtoms(pattern.Expression, pattern.Flags)
		useMasks := !accelerated && maskAccelerated
		if accelerated && maskAccelerated && hasUnboundedAtoms(atoms) {
			_, maskLength := maskAtomScore(maskAtoms)
			useMasks = maskLength >= shortestAtom(atoms)+4
		}
		if useMasks {
			if db.patterns[index].start.kind == startUnbounded && !pattern.Flags.has(UTF8) {
				db.patterns[index].start = maskStartConstraint(maskAtoms)
			}
			for _, atom := range maskAtoms {
				triggers = append(triggers, trigger{
					masks: atom.masks, pattern: uint32(index),
					prefixMin: atom.prefixMin, prefixMax: atom.prefixMax,
				})
			}
			continue
		}
		if !accelerated {
			db.always = append(db.always, uint32(index))
			continue
		}
		if db.patterns[index].start.kind == startUnbounded && !pattern.Flags.has(UTF8) {
			db.patterns[index].start = atomStart
		}
		for _, atom := range atoms {
			triggers = append(triggers, trigger{
				text: atom.text, pattern: uint32(index), caseless: atom.caseless,
				prefixMin: atom.prefixMin, prefixMax: atom.prefixMax,
			})
		}
	}
	db.matcher = newLiteralMatcher(triggers)
	db.size = estimateSize(db, triggers)
	return db, nil
}

func hasUnboundedAtoms(atoms []atom) bool {
	for _, candidate := range atoms {
		if candidate.prefixMax < 0 {
			return true
		}
	}
	return false
}

func shortestAtom(atoms []atom) int {
	shortest := int(^uint(0) >> 1)
	for _, candidate := range atoms {
		shortest = min(shortest, len(candidate.text))
	}
	return shortest
}

// Scan searches data and calls handler for every reported match.
func (db *Database) Scan(data []byte, scratch *Scratch, handler MatchHandler) error {
	return db.scan(data, scratch, handler, true)
}

func (db *Database) scan(data []byte, scratch *Scratch, handler MatchHandler, ordered bool) error {
	if db == nil || handler == nil {
		return ErrInvalid
	}
	if scratch == nil {
		scratch = NewScratch(db)
	}
	if err := scratch.prepare(len(db.patterns)); err != nil {
		return err
	}
	defer scratch.release()
	if len(scratch.nfa.marks) < db.maxProgram {
		scratch.nfa = newNFAScratch(db.maxProgram)
	}
	report := handler
	if ordered {
		handler = func(match Match) error {
			scratch.matches = append(scratch.matches, queuedMatch{match: match, pattern: scratch.collectFor})
			return nil
		}
	}

	for _, pattern := range db.always {
		scratch.addCandidate(pattern)
	}
	for _, index := range db.always {
		if err := db.scanPattern(data, 0, len(data), index, scratch, handler, 0, len(data)); err != nil {
			return err
		}
	}
	db.matcher.scan(data, scratch)
	ascii, asciiChecked := true, false
	for _, pattern := range scratch.candidates {
		first := scratch.hitHeads[pattern]
		if first < 0 {
			continue
		}
		compiled := &db.patterns[pattern]
		unbounded := false
		for current := first; current >= 0; current = scratch.hits[current].next {
			unbounded = unbounded || scratch.hits[current].unbounded && compiled.start.kind == startUnbounded
		}
		if compiled.source.Flags.has(SingleMatch) && scratch.reported[pattern] == scratch.generation {
			continue
		}
		if unbounded {
			if err := db.scanPattern(data, 0, len(data), pattern, scratch, handler, 0, len(data)); err != nil {
				return err
			}
			continue
		}
		for current := first; current >= 0; current = scratch.hits[current].next {
			hit := scratch.hits[current]
			startMin, startMax := int(hit.startMin), int(hit.startMax)
			if hit.unbounded {
				var ok bool
				startMin, startMax, ok = compiled.start.bounds(data, int(hit.atomStart), startMax)
				if !ok {
					continue
				}
			}
			scale := 1
			if compiled.source.Flags.has(UTF8) {
				if !asciiChecked {
					ascii = isASCII(data)
					asciiChecked = true
				}
				if !ascii {
					startMin = int(hit.wideStartMin)
					scale = 4
				}
			}
			end := len(data)
			if compiled.width >= 0 {
				end = min(end, startMax+compiled.width*scale)
			}
			if err := db.scanPattern(data, startMin, end, pattern, scratch, handler, startMin, startMax); err != nil {
				return err
			}
			if compiled.source.Flags.has(SingleMatch) && scratch.reported[pattern] == scratch.generation {
				break
			}
		}
	}
	if !ordered {
		return nil
	}
	slices.SortFunc(scratch.matches, func(left, right queuedMatch) int {
		if left.match.To != right.match.To {
			if left.match.To < right.match.To {
				return -1
			}
			return 1
		}
		if left.pattern != right.pattern {
			return int(left.pattern) - int(right.pattern)
		}
		if left.match.From < right.match.From {
			return -1
		}
		if left.match.From > right.match.From {
			return 1
		}
		return 0
	})
	var previous queuedMatch
	for position, queued := range scratch.matches {
		if position > 0 && queued.pattern == previous.pattern && queued.match.To == previous.match.To {
			continue
		}
		if err := report(queued.match); err != nil {
			return err
		}
		previous = queued
	}
	return nil
}

func (db *Database) scanPattern(data []byte, start, end int, index uint32, scratch *Scratch, handler MatchHandler, startMin, startMax int) error {
	compiled := &db.patterns[index]
	if compiled.literalGuard != nil && !compiled.literalGuard.possible(data, startMin, startMax, end) {
		return nil
	}
	if len(compiled.guards) > 0 && !matchRunGuards(data, startMin, startMax, end, compiled.guards) {
		return nil
	}
	if compiled.dfa != nil && !compiled.dfa.possible(data, start, end, startMin, startMax) {
		return nil
	}
	scratch.collectFor = index
	return scanNFA(data, start, end, startMin, startMax, index, compiled, scratch, handler)
}

func isASCII(data []byte) bool {
	for len(data) >= 8 {
		if binary.LittleEndian.Uint64(data)&0x8080808080808080 != 0 {
			return false
		}
		data = data[8:]
	}
	for _, value := range data {
		if value >= 0x80 {
			return false
		}
	}
	return true
}

// Match reports whether any expression matches data.
func (db *Database) Match(data []byte, scratch *Scratch) (bool, error) {
	matched := false
	err := db.scan(data, scratch, func(Match) error {
		matched = true
		return ErrScanTerminated
	}, false)
	if err == ErrScanTerminated {
		err = nil
	}
	return matched, err
}

// Size returns the approximate bytes held by the database.
func (db *Database) Size() int {
	if db == nil {
		return 0
	}
	return db.size
}

// Stats returns counts useful when tuning a pattern set.
func (db *Database) Stats() CompileStats {
	if db == nil {
		return CompileStats{}
	}
	stats := CompileStats{
		Patterns:  len(db.patterns),
		AlwaysRun: len(db.always),
	}
	for _, candidate := range db.matcher.hashed.triggers {
		if candidate.caseless {
			stats.CaselessTriggers++
		} else {
			stats.SensitiveTriggers++
		}
	}
	for _, candidate := range db.matcher.hashPairs.triggers {
		if len(candidate.masks) > 0 {
			stats.MaskTriggers++
			continue
		}
		if candidate.caseless {
			stats.CaselessTriggers++
		} else {
			stats.SensitiveTriggers++
		}
	}
	stats.HashTriggers = len(db.matcher.hashed.triggers)
	stats.HashLiterals = len(db.matcher.hashed.groups)
	for _, candidate := range db.matcher.hashPairs.triggers {
		if len(candidate.text) > 0 {
			stats.PairTriggers++
		}
	}
	stats.Accelerated = stats.Patterns - stats.AlwaysRun
	for i := range db.patterns {
		stats.RunGuards += len(db.patterns[i].guards)
		if dfa := db.patterns[i].dfa; dfa != nil {
			stats.DFAPatterns++
			stats.DFAStates += len(dfa.next) / dfa.stride
		}
		if db.patterns[i].width >= 0 {
			stats.Bounded++
		}
	}
	guardClasses := make(map[*[256]bool]struct{})
	for i := range db.patterns {
		for _, guard := range db.patterns[i].guards {
			guardClasses[guard.lookup] = struct{}{}
		}
	}
	stats.GuardClasses = len(guardClasses)
	return stats
}

func nullable(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	case syntax.OpCapture:
		return nullable(re.Sub[0])
	case syntax.OpStar, syntax.OpQuest:
		return true
	case syntax.OpPlus:
		return nullable(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min == 0 || nullable(re.Sub[0])
	case syntax.OpConcat:
		for _, child := range re.Sub {
			if !nullable(child) {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		for _, child := range re.Sub {
			if nullable(child) {
				return true
			}
		}
	}
	return false
}

func maximumWidth(re *syntax.Regexp) int {
	_, maximum := asciiWidth(re)
	return maximum
}

func estimateSize(db *Database, triggers []trigger) int {
	const uint32Size = int(unsafe.Sizeof(uint32(0)))
	const uint16Size = int(unsafe.Sizeof(uint16(0)))
	size := int(unsafe.Sizeof(*db))
	size += len(db.patterns) * int(unsafe.Sizeof(compiledPattern{}))
	size += len(db.always) * uint32Size
	size += len(db.matcher.hashed.buckets) * int(unsafe.Sizeof(literalBucket{}))
	size += len(db.matcher.hashed.groups) * int(unsafe.Sizeof(literalGroup{}))
	size += len(db.matcher.hashPairs.triggerIDs) * uint32Size
	if db.matcher.fdr != nil {
		size += int(unsafe.Sizeof(*db.matcher.fdr))
	}
	for _, candidate := range triggers {
		size += int(unsafe.Sizeof(candidate))
		size += len(candidate.text)
		size += len(candidate.masks) * int(unsafe.Sizeof(byteMask{}))
	}
	guardClasses := make(map[*[256]bool]struct{})
	for _, pattern := range db.patterns {
		size += len(pattern.source.Expression)
		size += int(unsafe.Sizeof(*pattern.prog))
		size += len(pattern.prog.Inst) * int(unsafe.Sizeof(syntax.Inst{}))
		for _, instruction := range pattern.prog.Inst {
			size += len(instruction.Rune) * int(unsafe.Sizeof(rune(0)))
		}
		size += len(pattern.byteMasks) * int(unsafe.Sizeof(byteMask{}))
		size += (len(pattern.epsilon) + len(pattern.epsilonAt)) * uint32Size
		if pattern.startClosures != nil {
			size += int(unsafe.Sizeof(*pattern.startClosures)) + len(pattern.startClosures.terminals)*uint32Size
		}
		size += len(pattern.guards) * int(unsafe.Sizeof(runGuard{}))
		size += len(pattern.loops) * int(unsafe.Sizeof((*[256]bool)(nil)))
		for _, table := range pattern.loops {
			if table != nil {
				guardClasses[table] = struct{}{}
			}
		}
		if dfa := pattern.dfa; dfa != nil {
			size += int(unsafe.Sizeof(*dfa)) + uint16Size*(len(dfa.next)+len(dfa.search))
		}
		if guard := pattern.literalGuard; guard != nil {
			size += int(unsafe.Sizeof(*guard)) + len(guard.literals)*int(unsafe.Sizeof([]byte{}))
			for _, literal := range guard.literals {
				size += len(literal)
			}
		}
		for _, guard := range pattern.guards {
			guardClasses[guard.lookup] = struct{}{}
		}
	}
	size += len(guardClasses) * int(unsafe.Sizeof([256]bool{}))
	return size
}
