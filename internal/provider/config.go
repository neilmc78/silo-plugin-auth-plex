package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// Global config keys and fields. They must match manifest.json. The host
// reads the button label and icon keys itself; the plugin ignores them.
const (
	keyServer              = "server"
	fieldMachineIdentifier = "machine_identifier"
)

// machineIdentifierPattern matches a Plex Media Server machineIdentifier, a
// 40-character hex string in every release seen so far. It is checked loosely
// so a format change at Plex does not lock everyone out.
var machineIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9-]{8,128}$`)

// Config is the plugin's parsed global configuration.
type Config struct {
	// MachineIdentifier names the Plex Media Server a person must be able to
	// reach to sign in.
	MachineIdentifier string
}

// ParseConfig reads Configure or TestConnection entries. Missing keys are
// empty; it fails only on values of the wrong type.
func ParseConfig(entries []*pluginv1.ConfigEntry) (Config, error) {
	var cfg Config
	for _, entry := range entries {
		if entry.GetKey() != keyServer {
			continue
		}
		raw, ok := entry.GetValue().AsMap()[fieldMachineIdentifier]
		if !ok || raw == nil {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			return Config{}, fmt.Errorf("%s.%s must be a string", keyServer, fieldMachineIdentifier)
		}
		cfg.MachineIdentifier = strings.TrimSpace(value)
	}
	return cfg, nil
}

// Problem describes what keeps the configuration from working, or "".
func (c Config) Problem() string {
	switch {
	case c.MachineIdentifier == "":
		return "Enter the Plex server's machine identifier under Plex server."
	case !machineIdentifierPattern.MatchString(c.MachineIdentifier):
		return "The machine identifier should be the machineIdentifier value from your server's /identity page, letters and digits only."
	}
	return ""
}

// ClientIdentifier is the X-Plex-Client-Identifier this plugin uses. It is
// derived from the server, not generated at random, so every Silo node reads
// back PINs another node created.
func (c Config) ClientIdentifier() string {
	sum := sha256.Sum256([]byte("silo-plugin-auth-plex/" + c.MachineIdentifier))
	return "silo-" + hex.EncodeToString(sum[:12])
}
