package dns

import (
	"testing"
)

func TestDomainAllowList_IsDomainAllowed(t *testing.T) {
	tests := []struct {
		name      string
		exact     []string
		wildcards []string
		domain    string
		want      bool
	}{
		{
			name:   "exact match",
			exact:  []string{"target.com"},
			domain: "target.com",
			want:   true,
		},
		{
			name:   "exact match case insensitive",
			exact:  []string{"Target.COM"},
			domain: "target.com",
			want:   true,
		},
		{
			name:   "exact match query uppercase",
			exact:  []string{"target.com"},
			domain: "TARGET.COM",
			want:   true,
		},
		{
			name:   "exact match with trailing dot",
			exact:  []string{"target.com"},
			domain: "target.com.",
			want:   true,
		},
		{
			name:   "exact match entry has trailing dot",
			exact:  []string{"target.com."},
			domain: "target.com",
			want:   true,
		},
		{
			name:      "wildcard match single level subdomain",
			wildcards: []string{"*.target.com"},
			domain:    "foo.target.com",
			want:      true,
		},
		{
			name:      "wildcard match multi level subdomain",
			wildcards: []string{"*.target.com"},
			domain:    "bar.baz.target.com",
			want:      true,
		},
		{
			name:      "wildcard does NOT match base domain",
			wildcards: []string{"*.target.com"},
			domain:    "target.com",
			want:      false,
		},
		{
			name:      "wildcard match case insensitive",
			wildcards: []string{"*.Target.COM"},
			domain:    "FOO.target.com",
			want:      true,
		},
		{
			name:      "wildcard with trailing dot query",
			wildcards: []string{"*.target.com"},
			domain:    "foo.target.com.",
			want:      true,
		},
		{
			name:   "no match returns false",
			exact:  []string{"target.com"},
			domain: "other.com",
			want:   false,
		},
		{
			name:      "no match wildcard unrelated domain",
			wildcards: []string{"*.target.com"},
			domain:    "foo.other.com",
			want:      false,
		},
		{
			name:   "empty allow list matches nothing",
			exact:  []string{},
			domain: "anything.com",
			want:   false,
		},
		{
			name:      "exact and wildcard combined - exact matches",
			exact:     []string{"target.com"},
			wildcards: []string{"*.target.com"},
			domain:    "target.com",
			want:      true,
		},
		{
			name:      "exact and wildcard combined - wildcard matches",
			exact:     []string{"target.com"},
			wildcards: []string{"*.target.com"},
			domain:    "sub.target.com",
			want:      true,
		},
		{
			name:   "subdomain not matched by exact entry",
			exact:  []string{"target.com"},
			domain: "sub.target.com",
			want:   false,
		},
		{
			name:      "wildcard does not match partial suffix",
			wildcards: []string{"*.target.com"},
			domain:    "nottarget.com",
			want:      false,
		},
		{
			name:      "wildcard does not match embedded",
			wildcards: []string{"*.target.com"},
			domain:    "footarget.com",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dal := NewDomainAllowList(tt.exact, tt.wildcards)
			got := dal.IsDomainAllowed(tt.domain)
			if got != tt.want {
				t.Errorf("IsDomainAllowed(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Target.COM", "target.com"},
		{"target.com.", "target.com"},
		{"TARGET.COM.", "target.com"},
		{"already.lower", "already.lower"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeDomain(tt.input)
			if got != tt.want {
				t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
