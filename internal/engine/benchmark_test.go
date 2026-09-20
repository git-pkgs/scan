package engine

import "testing"

func benchmarkDatabase(b *testing.B) *Database {
	b.Helper()
	patterns := make([]*Pattern, 400)
	for i := range patterns {
		patterns[i] = &Pattern{
			Expression: `prefix` + string(rune('A'+i%26)) + `-[0-9A-Za-z]{24}`,
			Flags:      SingleMatch,
			ID:         uint(i),
		}
	}
	db, err := Compile(patterns...)
	if err != nil {
		b.Fatal(err)
	}
	return db
}

func BenchmarkScanNoMatch(b *testing.B) {
	db := benchmarkDatabase(b)
	scratch := NewScratch(db)
	data := []byte("package main\n\nfunc main() { println(\"ordinary source file\") }\n")
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if err := db.Scan(data, scratch, func(Match) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
}
