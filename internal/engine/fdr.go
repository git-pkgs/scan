/*
 * Copyright (c) 2015-2019, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package engine

import (
	"encoding/binary"
	"math"
	"math/bits"
	"sort"
)

const fdrDomainMask = 1<<13 - 1

type fdrMatcher struct {
	table   [fdrDomainMask + 1]uint64
	initial uint64
}

type fdrLiteral struct {
	masks []byteMask
}

func fdrLiterals(matcher *literalMatcher) []fdrLiteral {
	var literals []fdrLiteral
	for _, group := range matcher.hashed.groups {
		literals = append(literals, fdrLiteral{masks: fdrLiteralMasks(group.text[:group.pairEnd+1], group.caseless)})
	}
	for _, trigger := range matcher.hashPairs.triggers {
		masks := trigger.masks
		if len(trigger.text) > 0 {
			masks = fdrLiteralMasks(trigger.text, trigger.caseless)
		} else {
			masks = masks[:trigger.pairEnd+1]
		}
		literals = append(literals, fdrLiteral{masks: masks})
	}
	if len(literals) == 0 {
		return nil
	}
	sort.SliceStable(literals, func(i, j int) bool {
		left, right := literals[i].masks, literals[j].masks
		if len(left) != len(right) {
			return len(left) < len(right)
		}
		for offset := len(left) - 1; offset >= 0; offset-- {
			for word := range left[offset] {
				if left[offset][word] != right[offset][word] {
					return left[offset][word] < right[offset][word]
				}
			}
		}
		return false
	})
	return literals
}

func compileFDR(matcher *literalMatcher) *fdrMatcher {
	literals := fdrLiterals(matcher)
	if len(literals) == 0 {
		return nil
	}
	return buildFDR(optimizeFDRBuckets(partitionFDR(literals)))
}

func buildFDR(groups [][]fdrLiteral) *fdrMatcher {
	result := new(fdrMatcher)
	for i := range result.table {
		result.table[i] = ^uint64(0)
	}
	for bucket, literals := range groups {
		minimum := 8
		for _, literal := range literals {
			minimum = min(minimum, len(literal.masks))
			result.addLiteral(bucket, literal.masks)
		}
		for position := 0; position < minimum-1; position++ {
			result.initial |= uint64(1) << (position*8 + bucket)
		}
		var unused uint64
		for position := minimum; position < 8; position++ {
			unused |= uint64(1) << (position*8 + bucket)
		}
		for i := range result.table {
			result.table[i] &^= unused
		}
	}
	return result
}

func fdrLiteralMasks(text []byte, caseless bool) []byteMask {
	masks := make([]byteMask, len(text))
	for i, value := range text {
		masks[i].add(value)
		if caseless && lowerASCII(value) >= 'a' && lowerASCII(value) <= 'z' {
			masks[i].add(lowerASCII(value))
			masks[i].add(lowerASCII(value) - ('a' - 'A'))
		}
	}
	return masks
}

func partitionFDR(literals []fdrLiteral) [][]fdrLiteral {
	count := len(literals)
	buckets := min(8, count)
	factors := make([]float64, count+1)
	for i := range factors {
		factors[i] = math.Pow(float64(i), 1.05)
	}
	scores := make([][]float64, buckets+1)
	cuts := make([][]int, buckets+1)
	for i := range scores {
		scores[i] = make([]float64, count+1)
		cuts[i] = make([]int, count+1)
		for j := range scores[i] {
			scores[i][j] = math.Inf(1)
		}
	}
	scores[0][0] = 0
	for bucket := 1; bucket <= buckets; bucket++ {
		for end := bucket; end <= count; end++ {
			for start := bucket - 1; start < end; start++ {
				length := float64(min(8, len(literals[start].masks)))
				score := scores[bucket-1][start] + factors[end-start]/(length*length*length)
				if score < scores[bucket][end] {
					scores[bucket][end], cuts[bucket][end] = score, start
				}
			}
		}
	}
	result := make([][]fdrLiteral, buckets)
	end := count
	for bucket := buckets; bucket > 0; bucket-- {
		start := cuts[bucket][end]
		result[bucket-1] = literals[start:end]
		end = start
	}
	return result
}

func (matcher *fdrMatcher) addLiteral(bucket int, masks []byteMask) {
	for position := 0; position < min(8, len(masks)); position++ {
		current := masks[len(masks)-1-position]
		next := ^uint32(0)
		if position > 0 {
			next = 0
			for value := 0; value < 256; value++ {
				if masks[len(masks)-position].contains(byte(value)) {
					next |= uint32(1) << (value & 31)
				}
			}
		}
		bit := uint64(1) << (position*8 + bucket)
		for value := 0; value < 256; value++ {
			if !current.contains(byte(value)) {
				continue
			}
			for remaining := next; remaining != 0; remaining &= remaining - 1 {
				key := value | bits.TrailingZeros32(remaining)<<8
				matcher.table[key] &^= bit
			}
		}
	}
}

func (m *literalMatcher) scanFDR(data []byte, scratch *Scratch) {
	state := m.fdr.initial
	table := &m.fdr.table
	offset := 0
	for ; offset+8 < len(data); offset += 8 {
		raw := binary.LittleEndian.Uint64(data[offset:])
		a := table[raw&fdrDomainMask]
		b := table[raw>>8&fdrDomainMask]
		c := table[raw>>16&fdrDomainMask]
		d := table[raw>>24&fdrDomainMask]
		e := table[raw>>32&fdrDomainMask]
		f := table[raw>>40&fdrDomainMask]
		g := table[raw>>48&fdrDomainMask]
		h := table[(raw>>56|uint64(data[offset+8])<<8)&fdrDomainMask]
		candidates := ^(state | a | b<<8 | c<<16 | d<<24 | e<<32 | f<<40 | g<<48 | h<<56)
		state = b>>56 | c>>48 | d>>40 | e>>32 | f>>24 | g>>16 | h>>8
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

func (m *literalMatcher) confirmFDR(data []byte, offset int, scratch *Scratch) {
	if offset >= 2 {
		window := uint32(lowerASCII(data[offset-2]))<<16 | uint32(lowerASCII(data[offset-1]))<<8 | uint32(lowerASCII(data[offset]))
		key := literalHash(window)
		if m.hashed.present[key>>6]&(1<<(key&63)) != 0 {
			m.hashed.confirm(data, offset, window, key, scratch)
		}
	}
	if offset >= 1 {
		key := uint16(data[offset-1])<<8 | uint16(data[offset])
		if m.hashPairs.present[key>>6]&(1<<(key&63)) != 0 {
			m.hashPairs.confirm(data, offset, key, scratch)
		}
	}
}
