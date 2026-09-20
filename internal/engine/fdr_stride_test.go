package engine

import (
	"encoding/binary"
	"math/bits"
)

func (m *literalMatcher) scanFDRStride2(data []byte, scratch *Scratch) {
	state := m.fdr.initial
	table := &m.fdr.table
	offset := 0
	for ; offset+8 <= len(data); offset += 8 {
		raw := binary.LittleEndian.Uint64(data[offset:])
		a := table[raw&fdrDomainMask]
		c := table[raw>>16&fdrDomainMask]
		e := table[raw>>32&fdrDomainMask]
		g := table[raw>>48&fdrDomainMask]
		candidates := ^(state | a | c<<16 | e<<32 | g<<48)
		state = c>>48 | e>>32 | g>>16
		for candidates != 0 {
			position := bits.TrailingZeros64(candidates) / 8
			candidates &^= uint64(255) << (position * 8)
			m.confirmFDR(data, offset+position, scratch)
		}
	}
	for ; offset < len(data); offset++ {
		key := uint16(data[offset])
		if offset+1 < len(data) {
			key |= uint16(data[offset+1]&31) << 8
		}
		state |= table[key]
		if byte(^state) != 0 {
			m.confirmFDR(data, offset, scratch)
		}
		state >>= 8
	}
}
