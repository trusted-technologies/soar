package docker

import "testing"

// commandArgs backs the image execution contract: the panel's invocation is
// split into container argv with POSIX word splitting so an arbitrary image
// boots the requested command instead of its own entrypoint.
func TestCommandArgs(t *testing.T) {
	tests := []struct {
		name       string
		invocation string
		want       []string
	}{
		{name: "empty", invocation: "", want: nil},
		{name: "whitespace only", invocation: "   ", want: nil},
		{name: "simple", invocation: "node server.js", want: []string{"node", "server.js"}},
		{
			name:       "quoted argument",
			invocation: `python -c "print('hello world')"`,
			want:       []string{"python", "-c", "print('hello world')"},
		},
		{
			name:       "single quoted path with spaces",
			invocation: `java -jar '/opt/my app/server.jar' --nogui`,
			want:       []string{"java", "-jar", "/opt/my app/server.jar", "--nogui"},
		},
		{
			name:       "variable assignment prefix is dropped",
			invocation: "FOO=bar node index.mjs",
			want:       []string{"node", "index.mjs"},
		},
		{
			name:       "pipe falls back to naive splitting",
			invocation: "echo hi | grep h",
			want:       []string{"echo", "hi", "|", "grep", "h"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commandArgs(tt.invocation)
			if len(got) != len(tt.want) {
				t.Fatalf("commandArgs(%q) = %q, want %q", tt.invocation, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("commandArgs(%q) = %q, want %q", tt.invocation, got, tt.want)
				}
			}
		})
	}
}
