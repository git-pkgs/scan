package engine

import (
	"encoding/binary"
	"testing"
)

func TestLiteralIndexBounds(t *testing.T) {
	for _, stride := range []int{1, 7, 64, 1024, 65535} {
		var index literalIndex
		want := make(map[uint16][2]uint32)
		var length uint32
		for key := 0; key < 1<<16; key++ {
			if key%stride != 0 && key != (1<<16)-1 {
				continue
			}
			count := uint32(key%3 + 1)
			want[uint16(key)] = [2]uint32{length, length + count}
			index.offsets = append(index.offsets, length)
			index.present[key>>6] |= uint64(1) << (key & 63)
			length += count
		}
		index.finish(length)
		writer := databaseCodec{}
		writer.literalIndex(&index)
		reader := databaseCodec{data: writer.data, reading: true}
		var loaded literalIndex
		reader.literalIndex(&loaded)
		if writer.err != nil || reader.err != nil {
			t.Fatalf("write=%v read=%v", writer.err, reader.err)
		}
		for key, bounds := range want {
			for _, candidate := range []*literalIndex{&index, &loaded} {
				first, end := candidate.bounds(key)
				if first != bounds[0] || end != bounds[1] {
					t.Fatalf("stride=%d key=%d: [%d:%d], want %v", stride, key, first, end, bounds)
				}
			}
		}
	}
}

func TestLiteralIndexRejectsInconsistentEncoding(t *testing.T) {
	for _, corrupt := range []func([]byte){
		func(data []byte) { binary.LittleEndian.PutUint32(data[4:], 1) },
		func(data []byte) { data[((1<<16)+1)*4] = 1 },
	} {
		var index literalIndex
		index.finish(0)
		writer := databaseCodec{}
		writer.literalIndex(&index)
		corrupt(writer.data)
		reader := databaseCodec{data: writer.data, reading: true}
		var loaded literalIndex
		reader.literalIndex(&loaded)
		if reader.err == nil {
			t.Fatal("accepted inconsistent offsets and presence bitmap")
		}
	}
}
