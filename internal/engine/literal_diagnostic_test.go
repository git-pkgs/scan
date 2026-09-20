package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestSecretsLiteralConfirmationDiagnostics(t *testing.T) {
	if os.Getenv("SCAN_LITERAL_DIAGNOSTICS") == "" {
		t.Skip("set SCAN_LITERAL_DIAGNOSTICS=1")
	}
	rules, root := loadSecretsRules(t)
	db := compileSecretsRules(t, rules)
	matcher := &db.matcher.hashed
	lengths := make(map[int]int)
	for _, group := range matcher.groups {
		lengths[min(len(group.text), 8)]++
	}
	t.Logf("literal lengths capped at eight: %v", lengths)
	for _, path := range []string{"main.go", "betterleaks/detect/detect.go", "betterleaks/config/betterleaks.toml", "secrets"} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		calls, checks, fragments, confirmed := 0, 0, 0, 0
		failed := make([]int, len(matcher.groups))
		var window uint32
		for offset, value := range data {
			window = window<<8&0xffffff | uint32(lowerASCII(value))
			if offset < 2 {
				continue
			}
			key := literalHash(window)
			if matcher.present[key>>6]&(uint64(1)<<(key&63)) == 0 {
				continue
			}
			calls++
			for _, bucket := range matcher.buckets[matcher.offsets[key]:matcher.offsets[int(key)+1]] {
				id := bucket.group
				checks++
				group := &matcher.groups[id]
				if group.fragment != window {
					continue
				}
				fragments++
				start := offset - group.pairEnd
				end := start + len(group.text)
				if start < 0 || end > len(data) {
					failed[id]++
					continue
				}
				matched := bytes.Equal(data[start:end], group.text)
				if group.caseless {
					matched = equalFoldASCII(data[start:end], group.text)
				}
				if matched {
					confirmed++
				} else {
					failed[id]++
				}
			}
		}
		t.Logf("%s: bytes=%d calls=%d group_checks=%d fragments=%d confirmed=%d", path, len(data), calls, checks, fragments, confirmed)
		ids := make([]int, len(failed))
		for i := range ids {
			ids[i] = i
		}
		sort.Slice(ids, func(i, j int) bool { return failed[ids[i]] > failed[ids[j]] })
		for _, id := range ids[:min(8, len(ids))] {
			group := &matcher.groups[id]
			t.Logf("  %q failures=%d fragment=%q", group.text, failed[id], group.text[group.pairEnd-2:group.pairEnd+1])
		}
	}
}
