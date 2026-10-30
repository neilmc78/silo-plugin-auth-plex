// Command plugin is the Silo Plex sign-in plugin.
package main

import (
	_ "embed"
	"log/slog"
	"os"

	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"

	"github.com/neilmc78/silo-plugin-auth-plex/internal/provider"
)

// version is set at build time via -ldflags "-X main.version=...".
var version string

//go:embed manifest.json
var manifestJSON []byte

func main() {
	// go-plugin forwards the plugin's stderr to the host log.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	plexProvider := provider.New(logger)
	runtime.ServeManifestWithOptions(manifestJSON, version,
		runtime.CapabilityServers{
			AuthProvider: plexProvider,
			HttpRoutes:   &assetRoutes{},
		},
		runtime.WithAuthProviderChecks(plexProvider),
		runtime.WithConfigure(plexProvider.Configure),
	)
}
