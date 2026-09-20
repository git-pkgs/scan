/*
 * Copyright (c) 2015-2020, Intel Corporation
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
	"math/bits"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type teddyBucket struct {
	nibbles  [6]uint16
	literals int
}

type teddyFilter [6][16]byte

func (bucket teddyBucket) score() int64 {
	probability := int64(1)
	for _, mask := range bucket.nibbles {
		probability *= int64(bits.OnesCount16(mask))
	}
	return probability * int64(2+bucket.literals)
}

func mergeTeddyBuckets(left, right teddyBucket) teddyBucket {
	for i, mask := range right.nibbles {
		left.nibbles[i] |= mask
	}
	left.literals += right.literals
	return left
}

func newTeddyFilter(matcher *literalMatcher) teddyFilter {
	var buckets []teddyBucket
	add := func(masks [3]byteMask) {
		bucket := teddyBucket{literals: 1}
		for position, mask := range masks {
			for value := 0; value < 256; value++ {
				if mask.contains(byte(value)) {
					bucket.nibbles[position*2] |= 1 << (value & 15)
					bucket.nibbles[position*2+1] |= 1 << (value >> 4)
				}
			}
		}
		buckets = append(buckets, bucket)
	}
	literalMask := func(value byte, caseless bool) byteMask {
		var mask byteMask
		mask.add(value)
		if caseless && lowerASCII(value) >= 'a' && lowerASCII(value) <= 'z' {
			mask.add(lowerASCII(value))
			mask.add(lowerASCII(value) - ('a' - 'A'))
		}
		return mask
	}
	for _, group := range matcher.hashed.groups {
		var masks [3]byteMask
		for i := range masks {
			masks[i] = literalMask(group.text[group.pairEnd-2+i], group.caseless)
		}
		add(masks)
	}
	for _, trigger := range matcher.hashPairs.triggers {
		var masks [3]byteMask
		for value := 0; value < 256; value++ {
			masks[0].add(byte(value))
		}
		if len(trigger.text) > 0 {
			masks[1] = literalMask(trigger.text[0], trigger.caseless)
			masks[2] = literalMask(trigger.text[1], trigger.caseless)
		} else {
			masks[1] = trigger.masks[trigger.pairEnd-1]
			masks[2] = trigger.masks[trigger.pairEnd]
		}
		add(masks)
	}
	for len(buckets) > 8 {
		bestScore := int64(^uint64(0) >> 1)
		first, second := 0, 1
		for i, left := range buckets {
			for j := i + 1; j < len(buckets); j++ {
				right := buckets[j]
				score := mergeTeddyBuckets(left, right).score() - left.score() - right.score()
				if score < bestScore {
					bestScore, first, second = score, i, j
				}
			}
		}
		buckets[first] = mergeTeddyBuckets(buckets[first], buckets[second])
		buckets = append(buckets[:second], buckets[second+1:]...)
	}
	var filter teddyFilter
	for id, bucket := range buckets {
		for position, mask := range bucket.nibbles {
			for nibble := range filter[position] {
				if mask&(1<<nibble) != 0 {
					filter[position][nibble] |= 1 << id
				}
			}
		}
	}
	return filter
}

func (filter *teddyFilter) candidate(first, second, third byte) byte {
	return filter[0][first&15] & filter[1][first>>4] & filter[2][second&15] & filter[3][second>>4] & filter[4][third&15] & filter[5][third>>4]
}

func (filter *teddyFilter) scan(matcher *literalMatcher, data []byte, scratch *Scratch) (int, int) {
	candidates, blocks := 0, 0
	lastBlock := -1
	for offset := 1; offset < len(data); offset++ {
		if offset >= 2 {
			if filter.candidate(data[offset-2], data[offset-1], data[offset]) == 0 {
				continue
			}
			candidates++
			block := (offset - 2) / 16
			if block != lastBlock {
				blocks++
				lastBlock = block
			}
			window := uint32(lowerASCII(data[offset-2]))<<16 | uint32(lowerASCII(data[offset-1]))<<8 | uint32(lowerASCII(data[offset]))
			key := literalHash(window)
			if matcher.hashed.present[key>>6]&(1<<(key&63)) != 0 {
				matcher.hashed.confirm(data, offset, window, key, scratch)
			}
		}
		key := uint16(data[offset-1])<<8 | uint16(data[offset])
		if matcher.hashPairs.present[key>>6]&(1<<(key&63)) != 0 {
			matcher.hashPairs.confirm(data, offset, key, scratch)
		}
	}
	return candidates, blocks
}

func TestSecretsTeddyFilterDiagnostics(t *testing.T) {
	if os.Getenv("SCAN_TEDDY_DIAGNOSTICS") == "" {
		t.Skip("set SCAN_TEDDY_DIAGNOSTICS=1")
	}
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	filter := newTeddyFilter(&db.matcher)
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		scratch, reference := NewScratch(db), NewScratch(db)
		if err := scratch.prepare(len(db.patterns)); err != nil {
			t.Fatal(err)
		}
		if err := reference.prepare(len(db.patterns)); err != nil {
			t.Fatal(err)
		}
		candidates, blocks := filter.scan(&db.matcher, data, scratch)
		db.matcher.scan(data, reference)
		multiset := func(hits []literalHit) map[literalHit]int {
			result := make(map[literalHit]int)
			for _, hit := range hits {
				hit.next = -1
				result[hit]++
			}
			return result
		}
		if !reflect.DeepEqual(multiset(scratch.hits), multiset(reference.hits)) {
			t.Fatalf("%s: filtered hits differ", path)
		}
		scratch.release()
		reference.release()
		t.Logf("%s bytes=%d candidates=%d (%.2f%%) nonempty blocks=%d (%.2f%%)", path, len(data), candidates, 100*float64(candidates)/float64(len(data)), blocks, 1600*float64(blocks)/float64(len(data)))
	}
}
