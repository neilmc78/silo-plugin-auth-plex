// Package provider implements Silo's auth_provider.v1 capability with Plex
// sign-in. A person may sign in only while their Plex account can reach the
// configured Plex Media Server: its owner, or someone it is shared with.
package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/neilmc78/silo-plugin-auth-plex/internal/plex"
)

// Product is the name Plex shows on its sign-in page and in the person's list
// of authorized devices.
const Product = "Silo"

const issuer = "https://plex.tv"

// provider_state and refresh_state keys.
const (
	statePinID   = "pin_id"
	statePinCode = "pin_code"
	stateToken   = "plex_token"
)

// Plex sends the browser back as soon as the person approves the PIN, which
// can be a moment before the PIN reads back with its token.
const (
	pinPollAttempts = 6
	pinPollInterval = 500 * time.Millisecond
)

// Provider serves AuthProvider and AuthProviderChecks.
type Provider struct {
	pluginv1.UnimplementedAuthProviderServer
	pluginv1.UnimplementedAuthProviderChecksServer

	logger *slog.Logger
	// newClient builds the plex.tv client for a configuration. Tests point it
	// at a fake plex.tv.
	newClient func(Config) *plex.Client

	mu  sync.RWMutex
	cfg Config
}

var (
	_ pluginv1.AuthProviderServer       = (*Provider)(nil)
	_ pluginv1.AuthProviderChecksServer = (*Provider)(nil)
)

// New returns a provider that talks to the real plex.tv.
func New(logger *slog.Logger) *Provider {
	return &Provider{
		logger: logger,
		newClient: func(cfg Config) *plex.Client {
			return plex.New(cfg.ClientIdentifier(), Product)
		},
	}
}

// Configure stores whatever settings arrive. Missing settings are reported at
// sign-in and by the connection test, never here.
func (p *Provider) Configure(_ context.Context, entries []*pluginv1.ConfigEntry) error {
	cfg, err := ParseConfig(entries)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.cfg = cfg
	p.mu.Unlock()
	return nil
}

func (p *Provider) config() Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg
}

// Authenticate refuses passwords: the plugin declares only the oauth2 mode.
func (p *Provider) Authenticate(context.Context, *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "Plex sign-in does not take a password"), nil
}

// InitAuthorize creates a plex.tv PIN and sends the browser to Plex's sign-in
// page. Plex returns the browser to the forward URL unchanged, so the host's
// state and the PIN id ride on it as the callback's state and code.
func (p *Provider) InitAuthorize(ctx context.Context, req *pluginv1.InitAuthorizeRequest) (*pluginv1.InitAuthorizeResponse, error) {
	cfg := p.config()
	if problem := cfg.Problem(); problem != "" {
		return nil, errors.New(problem)
	}
	forward, err := url.Parse(req.GetRedirectUri())
	if err != nil || forward.Scheme == "" || forward.Host == "" {
		return nil, fmt.Errorf("host sent an unusable redirect URI")
	}
	client := p.newClient(cfg)
	pin, err := client.CreatePin(ctx)
	if err != nil {
		return nil, fmt.Errorf("create plex.tv PIN: %w", err)
	}
	pinID := strconv.FormatInt(pin.ID, 10)
	q := forward.Query()
	q.Set("state", req.GetState())
	q.Set("code", pinID)
	forward.RawQuery = q.Encode()

	state, err := structpb.NewStruct(map[string]any{statePinID: pinID, statePinCode: pin.Code})
	if err != nil {
		return nil, err
	}
	return &pluginv1.InitAuthorizeResponse{
		AuthorizeUrl:  client.AuthURL(pin.Code, forward.String()),
		ProviderState: state,
	}, nil
}

// ExchangeCode reads the approved PIN's token and checks the account's access
// to the server. The PIN code never leaves the host, so a code in the callback
// URL that names some other PIN is refused rather than followed.
func (p *Provider) ExchangeCode(ctx context.Context, req *pluginv1.ExchangeCodeRequest) (*pluginv1.AuthenticateResponse, error) {
	cfg := p.config()
	if problem := cfg.Problem(); problem != "" {
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, problem), nil
	}
	stored := req.GetProviderState().AsMap()
	pinID, _ := stored[statePinID].(string)
	pinCode, _ := stored[statePinCode].(string)
	if pinID == "" || pinCode == "" || req.GetCode() != pinID {
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "callback code does not match the PIN this sign-in created"), nil
	}
	id, err := strconv.ParseInt(pinID, 10, 64)
	if err != nil {
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "stored PIN id is not a number"), nil
	}

	client := p.newClient(cfg)
	token, err := p.awaitToken(ctx, client, id, pinCode)
	switch {
	case errors.Is(err, plex.ErrNotFound):
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "the plex.tv PIN expired before sign-in finished"), nil
	case err != nil:
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "read plex.tv PIN: "+err.Error()), nil
	case token == "":
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "the plex.tv PIN was not approved"), nil
	}

	account, verdict, detail := p.checkToken(ctx, client, cfg, token)
	if verdict != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE {
		denial := pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE
		switch verdict {
		case pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED:
			denial = pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED
		case pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED:
			denial = pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS
		}
		return deny(denial, detail), nil
	}
	return account, nil
}

// awaitToken reads the PIN until it carries a token or the attempts run out.
func (p *Provider) awaitToken(ctx context.Context, client *plex.Client, id int64, code string) (string, error) {
	for attempt := 0; ; attempt++ {
		pin, err := client.GetPin(ctx, id, code)
		if err != nil || pin.AuthToken != "" || attempt+1 >= pinPollAttempts {
			return pin.AuthToken, err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pinPollInterval):
		}
	}
}

// CheckAccount re-checks a signed-in account with its stored Plex token, so a
// person loses Silo access once the server is no longer shared with them.
func (p *Provider) CheckAccount(ctx context.Context, req *pluginv1.CheckAccountRequest) (*pluginv1.CheckAccountResponse, error) {
	cfg := p.config()
	if cfg.Problem() != "" {
		return &pluginv1.CheckAccountResponse{Status: pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE}, nil
	}
	token, _ := req.GetRefreshState().AsMap()[stateToken].(string)
	if token == "" {
		return &pluginv1.CheckAccountResponse{Status: pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED}, nil
	}
	account, verdict, detail := p.checkToken(ctx, p.newClient(cfg), cfg, token)
	if account != nil && account.GetExternalSubject() != req.GetExternalSubject() {
		// The stored token now belongs to someone else; never vouch for it.
		p.logger.Warn("plex token subject changed", "detail", "stored token answers for a different Plex account")
		return &pluginv1.CheckAccountResponse{Status: pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED}, nil
	}
	if verdict != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE {
		p.logger.Info("plex account re-check", "status", verdict.String(), "detail", detail)
		return &pluginv1.CheckAccountResponse{Status: verdict}, nil
	}
	return &pluginv1.CheckAccountResponse{Status: verdict, Account: account}, nil
}

// checkToken loads the account behind a Plex token and checks it can reach
// the configured server. The verdict uses CheckAccount's statuses:
// UNSUPPORTED for a token plex.tv refuses, since a revoked and an expired
// token look the same.
func (p *Provider) checkToken(ctx context.Context, client *plex.Client, cfg Config, token string) (*pluginv1.AuthenticateResponse, pluginv1.CheckAccountStatus, string) {
	user, err := client.User(ctx, token)
	if err != nil {
		return nil, tokenErrorStatus(err), "load plex.tv account: " + err.Error()
	}
	account, err := accountResponse(user, token)
	if err != nil {
		return nil, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE, err.Error()
	}
	resources, err := client.Resources(ctx, token)
	if err != nil {
		return account, tokenErrorStatus(err), "list plex.tv resources: " + err.Error()
	}
	if _, ok := plex.HasServer(resources, cfg.MachineIdentifier); !ok {
		return account, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED,
			"Plex account " + user.UUID + " cannot reach the configured Plex server"
	}
	return account, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE, ""
}

func tokenErrorStatus(err error) pluginv1.CheckAccountStatus {
	if errors.Is(err, plex.ErrUnauthorized) {
		return pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED
	}
	return pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE
}

// accountResponse maps a plex.tv account to Silo's identity. The subject is
// the account's uuid, which never changes; usernames and emails can.
func accountResponse(user plex.User, token string) (*pluginv1.AuthenticateResponse, error) {
	refresh, err := structpb.NewStruct(map[string]any{stateToken: token})
	if err != nil {
		return nil, err
	}
	display := strings.TrimSpace(user.Title)
	if display == "" {
		display = user.Username
	}
	resp := &pluginv1.AuthenticateResponse{
		ExternalSubject: user.UUID,
		Issuer:          issuer,
		Username:        user.Username,
		DisplayName:     display,
		Email:           strings.TrimSpace(user.Email),
		RefreshState:    refresh,
	}
	// plex.tv's "confirmed" says the account confirmed its email. When it is
	// absent the provider said nothing, and email_verified stays unset.
	if user.Confirmed != nil && resp.Email != "" {
		verified := *user.Confirmed
		resp.EmailVerified = &verified
	}
	if u, err := url.Parse(user.Thumb); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
		resp.PictureUrl = user.Thumb
	}
	return resp, nil
}

// deny is a refusal. external_subject stays empty so older hosts refuse too.
func deny(denial pluginv1.AuthDenial, detail string) *pluginv1.AuthenticateResponse {
	return &pluginv1.AuthenticateResponse{Denial: denial, DenialDetail: detail}
}
