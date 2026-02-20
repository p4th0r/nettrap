package hostport

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{"single port", "8080", []int{8080}, false},
		{"multiple ports", "8080,1080,443", []int{8080, 1080, 443}, false},
		{"with spaces", "8080 , 1080 , 443", []int{8080, 1080, 443}, false},
		{"empty string", "", nil, false},
		{"trailing comma", "8080,", []int{8080}, false},
		{"port 1", "1", []int{1}, false},
		{"port 65535", "65535", []int{65535}, false},
		{"port 0", "0", nil, true},
		{"port 65536", "65536", nil, true},
		{"negative port", "-1", nil, true},
		{"non-numeric", "abc", nil, true},
		{"mixed valid invalid", "8080,abc", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Parse(%q) expected error, got %v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.input, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Parse(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Parse(%q)[%d] = %d, want %d", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}
