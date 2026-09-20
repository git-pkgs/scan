package main

import "testing"

func TestRepeatCount(t *testing.T) {
	for _, test := range []struct {
		input string
		want  int
		valid bool
	}{
		{"", 3, true},
		{"1", 1, true},
		{"5", 5, true},
		{"0", 0, false},
		{"-1", 0, false},
		{"abc", 0, false},
		{"999999999999999999999999", 0, false},
	} {
		got, err := repeatCount(test.input)
		if got != test.want || (err == nil) != test.valid {
			t.Errorf("repeatCount(%q) = %d, %v; want %d, valid=%v", test.input, got, err, test.want, test.valid)
		}
	}
}
