//go:build darwin

package console

import (
	"testing"
)

func TestParseItemList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected []int
	}{
		{
			name:     "single item",
			input:    "3",
			max:      10,
			expected: []int{3},
		},
		{
			name:     "comma separated",
			input:    "1,3,5",
			max:      10,
			expected: []int{1, 3, 5},
		},
		{
			name:     "comma with spaces joined",
			input:    "1,3,5",
			max:      10,
			expected: []int{1, 3, 5},
		},
		{
			name:     "range",
			input:    "2-5",
			max:      10,
			expected: []int{2, 3, 4, 5},
		},
		{
			name:     "mixed",
			input:    "1,3-5,8",
			max:      10,
			expected: []int{1, 3, 4, 5, 8},
		},
		{
			name:     "out of range filtered",
			input:    "1,15,3",
			max:      10,
			expected: []int{1, 3},
		},
		{
			name:     "zero filtered",
			input:    "0,1,2",
			max:      10,
			expected: []int{1, 2},
		},
		{
			name:     "duplicates removed",
			input:    "1,1,2,2",
			max:      10,
			expected: []int{1, 2},
		},
		{
			name:     "range duplicates with singles",
			input:    "1-3,2",
			max:      10,
			expected: []int{1, 2, 3},
		},
		{
			name:     "empty input",
			input:    "",
			max:      10,
			expected: []int{},
		},
		{
			name:     "invalid input",
			input:    "abc",
			max:      10,
			expected: []int{},
		},
		{
			name:     "reverse range",
			input:    "5-2",
			max:      10,
			expected: []int{2, 3, 4, 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseItemList(tt.input, tt.max)
			if len(result) != len(tt.expected) {
				t.Errorf("parseItemList(%q, %d) = %v, want %v", tt.input, tt.max, result, tt.expected)
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("parseItemList(%q, %d)[%d] = %d, want %d", tt.input, tt.max, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestFormatTimestamp(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "2026-02-26T10:30:00-07:00",
			expected: "10:30:00",
		},
		{
			input:    "invalid",
			expected: "invalid",
		},
	}

	for _, tt := range tests {
		result := formatTimestamp(tt.input)
		if result != tt.expected {
			t.Errorf("formatTimestamp(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "text content",
			input:    []byte("Hello, world!\nThis is a test."),
			expected: false,
		},
		{
			name:     "binary with null",
			input:    []byte{0x48, 0x65, 0x6c, 0x00, 0x6f},
			expected: true,
		},
		{
			name:     "empty",
			input:    []byte{},
			expected: false,
		},
		{
			name:     "json content",
			input:    []byte(`{"key": "value", "number": 123}`),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBinary(tt.input)
			if result != tt.expected {
				t.Errorf("isBinary(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNewConsole(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New() returned nil")
	}
	if c.socketPath == "" {
		t.Error("socketPath should not be empty")
	}
	if c.alertCh == nil {
		t.Error("alertCh should not be nil")
	}
	if c.stopCh == nil {
		t.Error("stopCh should not be nil")
	}
}
