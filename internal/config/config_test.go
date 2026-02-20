package config

import "testing"

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid analyse mode",
			cfg: Config{
				Analyse: true,
				Command: []string{"curl", "https://example.com"},
				Timeout: 30,
			},
			wantErr: false,
		},
		{
			name: "valid allow mode",
			cfg: Config{
				AllowList: "example.com",
				Command:   []string{"curl", "https://example.com"},
				Timeout:   30,
			},
			wantErr: false,
		},
		{
			name: "valid allow-file mode",
			cfg: Config{
				AllowFile: "/path/to/file.txt",
				Command:   []string{"curl", "https://example.com"},
				Timeout:   30,
			},
			wantErr: false,
		},
		{
			name: "valid interactive mode",
			cfg: Config{
				Interactive: true,
				Command:     []string{"curl", "https://example.com"},
				Timeout:     30,
			},
			wantErr: false,
		},
		{
			name: "allow and allow-file combined",
			cfg: Config{
				AllowList: "example.com",
				AllowFile: "/path/to/file.txt",
				Command:   []string{"curl", "https://example.com"},
				Timeout:   30,
			},
			wantErr: false,
		},
		{
			name: "no mode specified",
			cfg: Config{
				Command: []string{"curl", "https://example.com"},
				Timeout: 30,
			},
			wantErr: true,
			errMsg:  "no mode specified",
		},
		{
			name: "conflicting modes - analyse and interactive",
			cfg: Config{
				Analyse:     true,
				Interactive: true,
				Command:     []string{"curl", "https://example.com"},
				Timeout:     30,
			},
			wantErr: true,
			errMsg:  "mutually exclusive",
		},
		{
			name: "conflicting modes - allow and analyse",
			cfg: Config{
				AllowList: "example.com",
				Analyse:   true,
				Command:   []string{"curl", "https://example.com"},
				Timeout:   30,
			},
			wantErr: true,
			errMsg:  "mutually exclusive",
		},
		{
			name: "no command specified",
			cfg: Config{
				Analyse: true,
				Command: []string{},
				Timeout: 30,
			},
			wantErr: true,
			errMsg:  "no command specified",
		},
		{
			name: "invalid timeout",
			cfg: Config{
				Analyse: true,
				Command: []string{"curl", "https://example.com"},
				Timeout: 0,
			},
			wantErr: true,
			errMsg:  "timeout must be positive",
		},
		{
			name: "negative timeout",
			cfg: Config{
				Analyse: true,
				Command: []string{"curl", "https://example.com"},
				Timeout: -5,
			},
			wantErr: true,
			errMsg:  "timeout must be positive",
		},
		{
			name: "invalid DNS upstream",
			cfg: Config{
				Analyse:     true,
				Command:     []string{"curl", "https://example.com"},
				Timeout:     30,
				DNSUpstream: "not-an-ip",
			},
			wantErr: true,
			errMsg:  "invalid DNS upstream",
		},
		{
			name: "valid DNS upstream",
			cfg: Config{
				Analyse:     true,
				Command:     []string{"curl", "https://example.com"},
				Timeout:     30,
				DNSUpstream: "1.1.1.1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfig_Mode(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "analyse mode",
			cfg:  Config{Analyse: true},
			want: "analyse",
		},
		{
			name: "interactive mode",
			cfg:  Config{Interactive: true},
			want: "interactive",
		},
		{
			name: "allow mode with list",
			cfg:  Config{AllowList: "example.com"},
			want: "allow",
		},
		{
			name: "allow mode with file",
			cfg:  Config{AllowFile: "/path/to/file"},
			want: "allow",
		},
		{
			name: "no mode",
			cfg:  Config{},
			want: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.Mode()
			if got != tt.want {
				t.Errorf("Mode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfig_DerivedValues(t *testing.T) {
	cfg := Config{
		SessionID: "a3f8",
		Subnet:    "10.200.42",
	}

	if got := cfg.HostVethIP(); got != "10.200.42.1" {
		t.Errorf("HostVethIP() = %q, want %q", got, "10.200.42.1")
	}

	if got := cfg.JailVethIP(); got != "10.200.42.2" {
		t.Errorf("JailVethIP() = %q, want %q", got, "10.200.42.2")
	}

	if got := cfg.SubnetCIDR(); got != "10.200.42.0/24" {
		t.Errorf("SubnetCIDR() = %q, want %q", got, "10.200.42.0/24")
	}

	if got := cfg.NamespaceName(); got != "nettrap-a3f8" {
		t.Errorf("NamespaceName() = %q, want %q", got, "nettrap-a3f8")
	}

	if got := cfg.HostVethName(); got != "veth-host-a3f8" {
		t.Errorf("HostVethName() = %q, want %q", got, "veth-host-a3f8")
	}

	if got := cfg.JailVethName(); got != "veth-jail-a3f8" {
		t.Errorf("JailVethName() = %q, want %q", got, "veth-jail-a3f8")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
