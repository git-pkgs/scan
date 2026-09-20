package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"regexp/syntax"
)

const databaseMagic = "SCANDB\x00\x05"
const databaseHeaderSize = len(databaseMagic) + sha256.Size

// Marshal encodes the compiled database in an architecture-independent format.
// The output can be embedded with go:embed. Format versions are library-specific.
func (db *Database) Marshal() ([]byte, error) {
	if db == nil || len(db.patterns) == 0 {
		return nil, ErrInvalid
	}
	c := databaseCodec{data: make([]byte, databaseHeaderSize, databaseHeaderSize+db.Size())}
	c.database(db)
	if c.err != nil {
		return nil, c.err
	}
	copy(c.data, databaseMagic)
	sum := sha256.Sum256(c.data[databaseHeaderSize:])
	copy(c.data[len(databaseMagic):], sum[:])
	return c.data, nil
}

// UnmarshalDatabase loads compiled tables without compiling expressions.
// It rejects incompatible formats and corrupt data and does not retain data.
// Only load artifacts produced by a trusted compiler; the checksum is not a signature.
func UnmarshalDatabase(data []byte) (*Database, error) {
	if len(data) < databaseHeaderSize || string(data[:len(databaseMagic)]) != databaseMagic {
		return nil, fmt.Errorf("database format: %w", ErrInvalid)
	}
	sum := sha256.Sum256(data[databaseHeaderSize:])
	if !bytes.Equal(sum[:], data[len(databaseMagic):databaseHeaderSize]) {
		return nil, fmt.Errorf("database checksum: %w", ErrInvalid)
	}
	c := databaseCodec{data: data[databaseHeaderSize:], reading: true}
	db := new(Database)
	c.database(db)
	if c.err != nil {
		return nil, c.err
	}
	if c.offset != len(c.data) || !validDatabase(db) {
		return nil, fmt.Errorf("database tables: %w", ErrInvalid)
	}
	for _, pattern := range db.patterns {
		db.maxProgram = max(db.maxProgram, len(pattern.prog.Inst))
	}
	triggers := append(append([]trigger(nil), db.matcher.hashed.triggers...), db.matcher.hashPairs.triggers...)
	db.size = estimateSize(db, triggers)
	return db, nil
}

type databaseCodec struct {
	data    []byte
	offset  int
	reading bool
	err     error
}

func (c *databaseCodec) fail() {
	if c.err == nil {
		c.err = fmt.Errorf("database encoding at byte %d: %w", c.offset, ErrInvalid)
	}
}

func (c *databaseCodec) number(value uint64, width int) uint64 {
	if c.err != nil {
		return 0
	}
	if c.reading {
		if width > len(c.data)-c.offset {
			c.fail()
			return 0
		}
		data := c.data[c.offset : c.offset+width]
		switch width {
		case 1:
			value = uint64(data[0])
		case 2:
			value = uint64(binary.LittleEndian.Uint16(data))
		case 4:
			value = uint64(binary.LittleEndian.Uint32(data))
		case 8:
			value = binary.LittleEndian.Uint64(data)
		}
		c.offset += width
		return value
	}
	switch width {
	case 1:
		c.data = append(c.data, byte(value))
	case 2:
		c.data = binary.LittleEndian.AppendUint16(c.data, uint16(value))
	case 4:
		c.data = binary.LittleEndian.AppendUint32(c.data, uint32(value))
	case 8:
		c.data = binary.LittleEndian.AppendUint64(c.data, value)
	}
	return value
}

func (c *databaseCodec) u32(v *uint32) {
	value := c.number(uint64(*v), 4)
	if c.reading {
		*v = uint32(value)
	}
}
func (c *databaseCodec) u64(v *uint64) {
	value := c.number(*v, 8)
	if c.reading {
		*v = value
	}
}
func (c *databaseCodec) octet(v *byte) {
	value := c.number(uint64(*v), 1)
	if c.reading {
		*v = byte(value)
	}
}

func (c *databaseCodec) integer(v *int) {
	value := int64(c.number(uint64(*v), 8))
	if c.reading {
		*v = int(value)
		if int64(*v) != value {
			c.fail()
		}
	}
}

func (c *databaseCodec) boolean(v *bool) {
	var value uint64
	if *v {
		value = 1
	}
	value = c.number(value, 1)
	if c.reading {
		*v = value == 1
	}
	if value > 1 {
		c.fail()
	}
}

func (c *databaseCodec) count(length, minimum int) int {
	value := c.number(uint64(length), 4)
	if c.reading && value > uint64((len(c.data)-c.offset)/minimum) || !c.reading && uint64(length) > uint64(^uint32(0)) {
		c.fail()
	}
	if c.err != nil {
		return 0
	}
	return int(value)
}

func codecSlice[T any](c *databaseCodec, values *[]T, minimum int, visit func(*T)) {
	length := c.count(len(*values), minimum)
	if c.reading {
		*values = make([]T, length)
	}
	for i := 0; i < length && c.err == nil; i++ {
		visit(&(*values)[i])
	}
}

func codecOptional[T any](c *databaseCodec, value **T, visit func(*T)) {
	present := *value != nil
	c.boolean(&present)
	if !present || c.err != nil {
		return
	}
	if c.reading {
		*value = new(T)
	}
	visit(*value)
}

func (c *databaseCodec) blob(value *[]byte) {
	length := c.count(len(*value), 1)
	if c.err != nil {
		return
	}
	if c.reading {
		*value = bytes.Clone(c.data[c.offset : c.offset+length])
		c.offset += length
	} else {
		c.data = append(c.data, (*value)...)
	}
}

func (c *databaseCodec) text(value *string) {
	if c.reading {
		length := c.count(0, 1)
		if c.err != nil {
			return
		}
		*value = string(c.data[c.offset : c.offset+length])
		c.offset += length
	} else {
		c.count(len(*value), 1)
		c.data = append(c.data, (*value)...)
	}
}

func (c *databaseCodec) mask(mask *byteMask) {
	for i := range mask {
		c.u64(&mask[i])
	}
}

func (c *databaseCodec) u16Slice(values *[]uint16) {
	length := c.count(len(*values), 2)
	if c.err != nil {
		return
	}
	if c.reading {
		*values = make([]uint16, length)
		data := c.data[c.offset : c.offset+length*2]
		for i := range *values {
			(*values)[i] = binary.LittleEndian.Uint16(data[i*2:])
		}
		c.offset += length * 2
	} else {
		start := len(c.data)
		c.data = append(c.data, make([]byte, length*2)...)
		for i, value := range *values {
			binary.LittleEndian.PutUint16(c.data[start+i*2:], value)
		}
	}
}

func (c *databaseCodec) database(db *Database) {
	codecSlice(c, &db.patterns, 64, c.pattern)
	codecSlice(c, &db.always, 4, c.u32)
	m := &db.matcher
	for i := range m.hashed.offsets {
		c.u32(&m.hashed.offsets[i])
	}
	for i := range m.hashed.present {
		c.u64(&m.hashed.present[i])
	}
	codecSlice(c, &m.hashed.buckets, 8, func(b *literalBucket) { c.u32(&b.fragment); c.u32(&b.group) })
	codecSlice(c, &m.hashed.triggers, 37, c.trigger)
	codecSlice(c, &m.hashed.groups, 35, c.group)
	for i := range m.hashPairs.offsets {
		c.u32(&m.hashPairs.offsets[i])
	}
	for i := range m.hashPairs.present {
		c.u64(&m.hashPairs.present[i])
	}
	codecSlice(c, &m.hashPairs.triggerIDs, 4, c.u32)
	codecSlice(c, &m.hashPairs.triggers, 37, c.trigger)
	codecOptional(c, &m.fdr, func(f *fdrMatcher) {
		for i := range f.table {
			c.u64(&f.table[i])
		}
		c.u64(&f.initial)
	})
	if c.reading && c.err == nil {
		lookups := make(map[[256]bool]*[256]bool)
		intern := func(table **[256]bool) {
			if *table == nil {
				return
			}
			if existing := lookups[**table]; existing != nil {
				*table = existing
			} else {
				lookups[**table] = *table
			}
		}
		for i := range db.patterns {
			for j := range db.patterns[i].guards {
				intern(&db.patterns[i].guards[j].lookup)
			}
			for j := range db.patterns[i].loops {
				intern(&db.patterns[i].loops[j])
			}
		}
	}
}

func (c *databaseCodec) pattern(p *compiledPattern) {
	c.text(&p.source.Expression)
	flags := uint32(p.source.Flags)
	c.u32(&flags)
	id := uint64(p.source.ID)
	c.u64(&id)
	if c.reading {
		p.source.Flags, p.source.ID = Flags(flags), uint(id)
		if uint64(p.source.ID) != id {
			c.fail()
		}
		p.prog = new(syntax.Prog)
	}
	c.integer(&p.prog.Start)
	c.integer(&p.prog.NumCap)
	codecSlice(c, &p.prog.Inst, 13, c.instruction)
	codecSlice(c, &p.byteMasks, 32, c.mask)
	codecSlice(c, &p.epsilon, 4, c.u32)
	codecSlice(c, &p.epsilonAt, 4, c.u32)
	codecOptional(c, &p.startClosures, func(v *contextClosures) {
		codecSlice(c, &v.terminals, 4, c.u32)
		for i := range v.offsets {
			c.u32(&v.offsets[i])
		}
	})
	codecSlice(c, &p.loops, 1, func(table **[256]bool) {
		codecOptional(c, table, func(v *[256]bool) {
			for i := range v {
				c.boolean(&v[i])
			}
		})
	})
	if c.reading && len(p.loops) == 0 {
		p.loops = nil
	}
	codecSlice(c, &p.guards, 312, func(g *runGuard) {
		c.mask(&g.mask)
		c.integer(&g.length)
		c.integer(&g.prefixMin)
		c.integer(&g.prefixMax)
		if c.reading {
			g.lookup = new([256]bool)
		}
		for i := range g.lookup {
			c.boolean(&g.lookup[i])
		}
	})
	codecOptional(c, &p.dfa, func(d *rejectDFA) {
		for i := range d.classes {
			c.octet(&d.classes[i])
		}
		c.integer(&d.stride)
		c.u16Slice(&d.next)
		c.u16Slice(&d.search)
	})
	codecOptional(c, &p.literalGuard, func(g *literalGuard) {
		c.integer(&g.newlines)
		c.mask(&g.before)
		codecSlice(c, &g.literals, 4, c.blob)
	})
	kind := byte(p.start.kind)
	c.octet(&kind)
	if c.reading {
		p.start.kind = startConstraintKind(kind)
	}
	c.octet(&p.start.value)
	c.mask(&p.start.mask)
	c.integer(&p.width)
}

func (c *databaseCodec) instruction(inst *syntax.Inst) {
	op := byte(inst.Op)
	c.octet(&op)
	if c.reading {
		inst.Op = syntax.InstOp(op)
	}
	c.u32(&inst.Out)
	c.u32(&inst.Arg)
	codecSlice(c, &inst.Rune, 4, func(r *rune) {
		v := uint32(*r)
		c.u32(&v)
		if c.reading {
			*r = rune(v)
		}
	})
}

func (c *databaseCodec) trigger(t *trigger) {
	c.blob(&t.text)
	codecSlice(c, &t.masks, 32, c.mask)
	c.u32(&t.fragment)
	c.integer(&t.pairEnd)
	c.u32(&t.pattern)
	c.boolean(&t.caseless)
	c.integer(&t.prefixMin)
	c.integer(&t.prefixMax)
}

func (c *databaseCodec) group(g *literalGroup) {
	c.blob(&g.text)
	c.integer(&g.pairEnd)
	c.integer(&g.checkAt)
	c.u32(&g.fragment)
	c.u32(&g.start)
	c.u32(&g.end)
	c.octet(&g.checkByte)
	c.octet(&g.checkFold)
	c.boolean(&g.caseless)
}
