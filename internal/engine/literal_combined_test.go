package engine

import "encoding/binary"

func (m *literalMatcher) scanHashCombined(data []byte, scratch *Scratch) {
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
		pairKey := uint16(previous)<<8 | uint16(raw>>56)
		hashHit := (hashed.present[key>>6] >> (key & 63)) & 1
		pairHit := (masked.present[pairKey>>6] >> (pairKey & 63)) & 1
		if hashHit|pairHit != 0 {
			if hashHit != 0 {
				hashed.confirm(data, offset, window, key, scratch)
			}
			if pairHit != 0 {
				masked.confirm(data, offset, pairKey, scratch)
			}
		}

		window = previousWindow<<16&0xffffff | uint32(folded>>48)
		key = literalHash(window)
		pairKey = uint16(raw >> 48)
		hashHit = (hashed.present[key>>6] >> (key & 63)) & 1
		pairHit = (masked.present[pairKey>>6] >> (pairKey & 63)) & 1
		if hashHit|pairHit != 0 {
			if hashHit != 0 {
				hashed.confirm(data, offset+1, window, key, scratch)
			}
			if pairHit != 0 {
				masked.confirm(data, offset+1, pairKey, scratch)
			}
		}

		window = uint32(folded>>40) & 0xffffff
		key = literalHash(window)
		pairKey = uint16(raw >> 40)
		hashHit = (hashed.present[key>>6] >> (key & 63)) & 1
		pairHit = (masked.present[pairKey>>6] >> (pairKey & 63)) & 1
		if hashHit|pairHit != 0 {
			if hashHit != 0 {
				hashed.confirm(data, offset+2, window, key, scratch)
			}
			if pairHit != 0 {
				masked.confirm(data, offset+2, pairKey, scratch)
			}
		}

		window = uint32(folded>>32) & 0xffffff
		key = literalHash(window)
		pairKey = uint16(raw >> 32)
		hashHit = (hashed.present[key>>6] >> (key & 63)) & 1
		pairHit = (masked.present[pairKey>>6] >> (pairKey & 63)) & 1
		if hashHit|pairHit != 0 {
			if hashHit != 0 {
				hashed.confirm(data, offset+3, window, key, scratch)
			}
			if pairHit != 0 {
				masked.confirm(data, offset+3, pairKey, scratch)
			}
		}

		window = uint32(folded>>24) & 0xffffff
		key = literalHash(window)
		pairKey = uint16(raw >> 24)
		hashHit = (hashed.present[key>>6] >> (key & 63)) & 1
		pairHit = (masked.present[pairKey>>6] >> (pairKey & 63)) & 1
		if hashHit|pairHit != 0 {
			if hashHit != 0 {
				hashed.confirm(data, offset+4, window, key, scratch)
			}
			if pairHit != 0 {
				masked.confirm(data, offset+4, pairKey, scratch)
			}
		}

		window = uint32(folded>>16) & 0xffffff
		key = literalHash(window)
		pairKey = uint16(raw >> 16)
		hashHit = (hashed.present[key>>6] >> (key & 63)) & 1
		pairHit = (masked.present[pairKey>>6] >> (pairKey & 63)) & 1
		if hashHit|pairHit != 0 {
			if hashHit != 0 {
				hashed.confirm(data, offset+5, window, key, scratch)
			}
			if pairHit != 0 {
				masked.confirm(data, offset+5, pairKey, scratch)
			}
		}

		window = uint32(folded>>8) & 0xffffff
		key = literalHash(window)
		pairKey = uint16(raw >> 8)
		hashHit = (hashed.present[key>>6] >> (key & 63)) & 1
		pairHit = (masked.present[pairKey>>6] >> (pairKey & 63)) & 1
		if hashHit|pairHit != 0 {
			if hashHit != 0 {
				hashed.confirm(data, offset+6, window, key, scratch)
			}
			if pairHit != 0 {
				masked.confirm(data, offset+6, pairKey, scratch)
			}
		}

		window = uint32(folded) & 0xffffff
		key = literalHash(window)
		pairKey = uint16(raw)
		hashHit = (hashed.present[key>>6] >> (key & 63)) & 1
		pairHit = (masked.present[pairKey>>6] >> (pairKey & 63)) & 1
		if hashHit|pairHit != 0 {
			if hashHit != 0 {
				hashed.confirm(data, offset+7, window, key, scratch)
			}
			if pairHit != 0 {
				masked.confirm(data, offset+7, pairKey, scratch)
			}
		}
		previous = byte(raw)
	}
	for ; offset < len(data); offset++ {
		current := data[offset]
		window = window<<8&0xffffff | uint32(lowerASCII(current))
		key := literalHash(window)
		pairKey := uint16(previous)<<8 | uint16(current)
		hashHit := (hashed.present[key>>6] >> (key & 63)) & 1
		pairHit := (masked.present[pairKey>>6] >> (pairKey & 63)) & 1
		if hashHit|pairHit != 0 {
			if hashHit != 0 {
				hashed.confirm(data, offset, window, key, scratch)
			}
			if pairHit != 0 {
				masked.confirm(data, offset, pairKey, scratch)
			}
		}
		previous = current
	}
}
