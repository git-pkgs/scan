//go:build go1.27 && goexperiment.simd

package engine

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"simd/archsimd"
	"testing"
)

func fdrShiftLeftBytes(value archsimd.Uint8x16, count uint64) archsimd.Uint8x16 {
	var zero archsimd.Uint8x16
	return value.ConcatShiftBytesRight(zero, 16-count)
}

func fdrShiftRightBytes(value archsimd.Uint8x16, count uint64) archsimd.Uint8x16 {
	var zero archsimd.Uint8x16
	return zero.ConcatShiftBytesRight(value, count)
}

func TestFDRSIMDShiftDirections(t *testing.T) {
	rng := rand.New(rand.NewSource(53))
	for iteration := 0; iteration < 1000; iteration++ {
		var data [16]byte
		for i := range data {
			data[i] = byte(rng.Intn(256))
		}
		value := archsimd.LoadUint8x16Array(&data)
		for count := 1; count < 16; count++ {
			var got, want [16]byte
			copy(want[count:], data[:16-count])
			fdrShiftLeftBytes(value, uint64(count)).StoreArray(&got)
			if !bytes.Equal(got[:], want[:]) {
				t.Fatalf("left %d: got=%x want=%x", count, got, want)
			}
			clear(want[:])
			copy(want[:16-count], data[count:])
			fdrShiftRightBytes(value, uint64(count)).StoreArray(&got)
			if !bytes.Equal(got[:], want[:]) {
				t.Fatalf("right %d: got=%x want=%x", count, got, want)
			}
		}
	}
}

func (m *literalMatcher) scanFDRSIMD(data []byte, scratch *Scratch) {
	var zero64 archsimd.Uint64x2
	state := zero64.SetElem(0, m.fdr.initial).ReshapeToUint8s()
	table := &m.fdr.table
	offset := 0
	for ; offset+8 < len(data); offset += 8 {
		raw := binary.LittleEndian.Uint64(data[offset:])
		a := zero64.SetElem(0, table[raw&fdrDomainMask]).ReshapeToUint8s()
		b := zero64.SetElem(0, table[raw>>8&fdrDomainMask]).ReshapeToUint8s()
		c := zero64.SetElem(0, table[raw>>16&fdrDomainMask]).ReshapeToUint8s()
		d := zero64.SetElem(0, table[raw>>24&fdrDomainMask]).ReshapeToUint8s()
		e := zero64.SetElem(0, table[raw>>32&fdrDomainMask]).ReshapeToUint8s()
		f := zero64.SetElem(0, table[raw>>40&fdrDomainMask]).ReshapeToUint8s()
		g := zero64.SetElem(0, table[raw>>48&fdrDomainMask]).ReshapeToUint8s()
		h := zero64.SetElem(0, table[(raw>>56|uint64(data[offset+8])<<8)&fdrDomainMask]).ReshapeToUint8s()
		ab := a.Or(fdrShiftLeftBytes(b, 1))
		cd := fdrShiftLeftBytes(c, 2).Or(fdrShiftLeftBytes(d, 3))
		ef := fdrShiftLeftBytes(e, 4).Or(fdrShiftLeftBytes(f, 5))
		gh := fdrShiftLeftBytes(g, 6).Or(fdrShiftLeftBytes(h, 7))
		state = state.Or(ab.Or(cd).Or(ef.Or(gh)))
		candidates := ^state.ReshapeToUint64s().GetElem(0)
		state = fdrShiftRightBytes(state, 8)
		for candidates != 0 {
			position := bits.TrailingZeros64(candidates) / 8
			candidates &^= uint64(255) << (position * 8)
			m.confirmFDR(data, offset+position, scratch)
		}
	}
	tail := state.ReshapeToUint64s().GetElem(0)
	for ; offset < len(data); offset++ {
		key := uint16(data[offset])
		if offset+1 < len(data) {
			key |= uint16(data[offset+1]&31) << 8
		}
		tail |= table[key]
		if byte(^tail) != 0 {
			m.confirmFDR(data, offset, scratch)
		}
		tail >>= 8
	}
}

func TestSecretsFDRSIMDAgrees(t *testing.T) {
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	db.matcher.fdr = compileFDR(&db.matcher)
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		scratch, control := NewScratch(db), NewScratch(db)
		if err := scratch.prepare(len(db.patterns)); err != nil {
			t.Fatal(err)
		}
		if err := control.prepare(len(db.patterns)); err != nil {
			t.Fatal(err)
		}
		db.matcher.scanFDRSIMD(data, scratch)
		db.matcher.scanFDR(data, control)
		if !reflect.DeepEqual(scratch.hits, control.hits) {
			t.Fatalf("%s: SIMD hits=%d Go hits=%d differ", path, len(scratch.hits), len(control.hits))
		}
		scratch.release()
		control.release()
	}
}

func BenchmarkSecretsFDRSIMD(b *testing.B) {
	rules, root := loadSecretsRules(b)
	db := compileSecretsRules(b, rules)
	db.matcher.fdr = compileFDR(&db.matcher)
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			b.Fatal(err)
		}
		for _, variant := range []struct {
			name string
			scan func([]byte, *Scratch)
		}{{"hash", db.matcher.scanHash}, {"fdr", db.matcher.scanFDR}, {"simd", db.matcher.scanFDRSIMD}} {
			b.Run(filepath.Base(path)+"/"+variant.name, func(b *testing.B) {
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
