package provider

import (
	"context"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// Test step IDs. They are stable; the host may key UI on them.
const (
	stepSettings = "settings"
	stepPlexTV   = "plex_tv"
)

// TestConnection checks the staged settings and that plex.tv issues sign-in
// PINs to this server. It cannot check the machine identifier without a Plex
// token; a wrong one shows up as every sign-in being refused.
func (p *Provider) TestConnection(ctx context.Context, req *pluginv1.AuthTestConnectionRequest) (*pluginv1.AuthTestConnectionResponse, error) {
	resp := &pluginv1.AuthTestConnectionResponse{}
	add := func(id, label string, ok bool, message string) {
		resp.Steps = append(resp.Steps, &pluginv1.AuthTestStep{Id: id, Label: label, Ok: ok, Message: message})
	}

	cfg, err := ParseConfig(req.GetConfig())
	if err == nil {
		if problem := cfg.Problem(); problem != "" {
			add(stepSettings, "Settings are valid", false, problem)
			return resp, nil
		}
	} else {
		add(stepSettings, "Settings are valid", false, err.Error())
		return resp, nil
	}
	add(stepSettings, "Settings are valid", true, "Plex server "+cfg.MachineIdentifier+" is set.")

	if _, err := p.newClient(cfg).CreatePin(ctx); err != nil {
		add(stepPlexTV, "plex.tv reachable", false, "Could not create a sign-in PIN: "+err.Error())
		return resp, nil
	}
	add(stepPlexTV, "plex.tv reachable", true, "plex.tv issued a sign-in PIN.")
	resp.Ok = true
	return resp, nil
}
