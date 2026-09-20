package engine

import (
	"encoding/binary"
	"math/bits"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type wideFDR struct {
	table   [1 << 16]uint64
	initial uint64
}

func compileWideFDR(matcher *literalMatcher) *wideFDR {
	f := new(wideFDR)
	for i := range f.table {
		f.table[i] = ^uint64(0)
	}
	for bucket, literals := range optimizeFDRBuckets(partitionFDR(fdrLiterals(matcher))) {
		minimum := 8
		for _, literal := range literals {
			masks := literal.masks
			minimum = min(minimum, len(masks))
			for position := 0; position < min(8, len(masks)); position++ {
				current := masks[len(masks)-1-position]
				bit := uint64(1) << (position*8 + bucket)
				for first := 0; first < 256; first++ {
					if !current.contains(byte(first)) {
						continue
					}
					for second := 0; second < 256; second++ {
						if position == 0 || masks[len(masks)-position].contains(byte(second)) {
							f.table[first|second<<8] &^= bit
						}
					}
				}
			}
		}
		for position := 0; position < minimum-1; position++ {
			f.initial |= uint64(1) << (position*8 + bucket)
		}
		var unused uint64
		for position := minimum; position < 8; position++ {
			unused |= uint64(1) << (position*8 + bucket)
		}
		for i := range f.table {
			f.table[i] &^= unused
		}
	}
	return f
}

func (f *wideFDR) scan(m *literalMatcher, data []byte, scratch *Scratch) {
	state := f.initial
	table := &f.table
	offset := 0
	for ; offset+8 < len(data); offset += 8 {
		raw := binary.LittleEndian.Uint64(data[offset:])
		a := table[uint16(raw)]
		b := table[uint16(raw>>8)]
		c := table[uint16(raw>>16)]
		d := table[uint16(raw>>24)]
		e := table[uint16(raw>>32)]
		f := table[uint16(raw>>40)]
		g := table[uint16(raw>>48)]
		h := table[uint16(raw>>56)|uint16(data[offset+8])<<8]
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
			key |= uint16(data[offset+1]) << 8
		}
		state |= table[key]
		if byte(^state) != 0 {
			m.confirmFDR(data, offset, scratch)
		}
		state >>= 8
	}
}

func TestSecretsWideFDR(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	wide := compileWideFDR(&db.matcher)
	if wide.initial != db.matcher.fdr.initial {
		t.Fatal("different initial state")
	}
	for key, reject := range wide.table {
		baseline := db.matcher.fdr.table[key&fdrDomainMask]
		if reject&baseline != baseline {
			t.Fatalf("key %d weakened rejection", key)
		}
	}
	for _, name := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/detect/detect_test.go", "betterleaks/config/betterleaks.toml", "hyperscan.db", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		fast, control := NewScratch(db), NewScratch(db)
		for _, scratch := range []*Scratch{fast, control} {
			if err := scratch.prepare(len(db.patterns)); err != nil {
				t.Fatal(err)
			}
		}
		wide.scan(&db.matcher, data, fast)
		db.matcher.scanHash(data, control)
		fast.release()
		control.release()
		multiset := func(hits []literalHit) map[literalHit]int {
			counts := make(map[literalHit]int)
			for _, hit := range hits {
				hit.next = -1
				counts[hit]++
			}
			return counts
		}
		if !reflect.DeepEqual(multiset(fast.hits), multiset(control.hits)) {
			t.Fatalf("%s: different hit multisets", name)
		}
	}
}

func BenchmarkSecretsWideFDR(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	wide := compileWideFDR(&db.matcher)
	for _, name := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			b.Fatal(err)
		}
		for _, variant := range []struct {
			name string
			scan func([]byte, *Scratch)
		}{{"64KB", db.matcher.scanFDR}, {"512KB", func(data []byte, scratch *Scratch) { wide.scan(&db.matcher, data, scratch) }}} {
			b.Run(filepath.Base(name)+"/"+variant.name, func(b *testing.B) {
				scratch := NewScratch(db)
				if err := scratch.prepare(len(db.patterns)); err != nil {
					b.Fatal(err)
				}
				variant.scan(data, scratch)
				scratch.release()
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					if err := scratch.prepare(len(db.patterns)); err != nil {
						b.Fatal(err)
					}
					variant.scan(data, scratch)
					scratch.release()
				}
			})
		}
	}
}
