package nuclei_scanner

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestNucleiArgsRestrictLocalNetwork(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "")
	if args := nucleiArgs("https://example.com", "low"); !slices.Contains(args, "-lna") {
		t.Fatalf("args %v: want -lna by default", args)
	}

	t.Setenv(config.EnvAllowPrivateTargets, "true")
	if args := nucleiArgs("https://example.com", "low"); slices.Contains(args, "-lna") {
		t.Fatalf("args %v: -lna must be omitted with ALLOW_PRIVATE_TARGETS=true", args)
	}
}

func TestNucleiArgsRateLimit(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		ok    bool
	}{
		{"unset", "", "30", true},
		{"set", "50", "50", true},
		{"spaces", " 50 ", "50", true},
		{"zero", "0", "30", false},
		{"negative", "-5", "30", false},
		{"not a number", "abc", "30", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(config.EnvNucleiRateLimit, tt.value)
			args := nucleiArgs("https://example.com", "low")
			i := slices.Index(args, "-rl")
			if i < 0 || i+1 >= len(args) || args[i+1] != tt.want {
				t.Fatalf("args %v: want -rl %s", args, tt.want)
			}
			if _, ok := rateLimit(); ok != tt.ok {
				t.Fatalf("rateLimit() ok = %v, want %v", ok, tt.ok)
			}
		})
	}
}

func TestNucleiArgsInteractsh(t *testing.T) {
	const token = "s3cret-token"
	tests := []struct {
		name, on, server, token string
		want                    []string // the interactsh part of the args
		invalid                 bool
	}{
		{"unset is off", "", "", "", []string{"-ni"}, false},
		{"off", "off", "https://oast.example.com", token, []string{"-ni"}, false},
		{"other value is off", "yes", "", "", []string{"-ni"}, false},
		{"on uses the public servers", "on", "", "", nil, false},
		{"true, any case", " TRUE ", "", "", nil, false},
		{"own server and token", "on", "https://oast.example.com", token, []string{"-iserver", "https://oast.example.com", "-itoken", token}, false},
		{"http server keeps it off", "on", "http://oast.example.com", token, []string{"-ni"}, true},
		{"bare host keeps it off", "on", "oast.example.com", "", []string{"-ni"}, true},
		{"credentials in URL keep it off", "on", "https://u:p@oast.example.com", "", []string{"-ni"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(config.EnvNucleiInteractsh, tt.on)
			t.Setenv(config.EnvNucleiInteractshServer, tt.server)
			t.Setenv(config.EnvNucleiInteractshToken, tt.token)

			got, err := interactshArgs()
			if (err != nil) != tt.invalid {
				t.Fatalf("err = %v, want invalid %v", err, tt.invalid)
			}
			if err != nil && (strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "u:p")) {
				t.Fatalf("err %q contains a secret", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("args = %v, want %v", got, tt.want)
			}
			args := nucleiArgs("https://example.com", "low")
			if slices.Contains(args, "-ni") != slices.Contains(tt.want, "-ni") {
				t.Fatalf("nucleiArgs %v: -ni does not match %v", args, tt.want)
			}
		})
	}
}

// An invalid server is logged at startup without the token.
func TestNewServiceWarnsAboutInvalidInteractshServerWithoutToken(t *testing.T) {
	t.Setenv(config.EnvNucleiInteractsh, "on")
	t.Setenv(config.EnvNucleiInteractshServer, "http://oast.example.com")
	t.Setenv(config.EnvNucleiInteractshToken, "s3cret-token")
	core, logs := observer.New(zapcore.DebugLevel)

	NewService(nil, zap.New(core))

	warns := logs.FilterMessageSnippet("interactsh").All()
	if len(warns) != 1 {
		t.Fatalf("logs = %v, want one interactsh warning", logs.All())
	}
	for _, f := range warns[0].Context {
		if strings.Contains(f.String, "s3cret") || (f.Interface != nil && strings.Contains(fmt.Sprint(f.Interface), "s3cret")) {
			t.Fatalf("warning field %s contains the token", f.Key)
		}
	}
}
