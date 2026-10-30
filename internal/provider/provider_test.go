package provider

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/neilmc78/silo-plugin-auth-plex/internal/plex"
)

const (
	testServer  = "0123456789abcdef0123456789abcdef01234567"
	otherServer = "fedcba9876543210fedcba9876543210fedcba98"
	testToken   = "tok-alice"
	testUUID    = "uuid-alice"
	testPinID   = 4242
	testPinCode = "pincode"
)

// fakePlex is a plex.tv with one PIN, approved for testToken, and one account.
type fakePlex struct {
	pinToken    string // token the PIN carries; empty means not approved
	userUUID    string
	servers     []string // machine identifiers the account can reach
	tokenStatus int      // non-zero: answer token calls with this status
}

func (f *fakePlex) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v2/pins", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": testPinID, "code": testPinCode})
	})
	mux.HandleFunc("GET /api/v2/pins/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "4242" || r.URL.Query().Get("code") != testPinCode {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{"id": testPinID, "code": testPinCode, "authToken": f.pinToken})
	})
	authed := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if f.tokenStatus != 0 {
				w.WriteHeader(f.tokenStatus)
				return
			}
			if r.Header.Get("X-Plex-Token") != testToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /api/v2/user", authed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"uuid": f.userUUID, "username": "alice", "title": "Alice", "email": "alice@example.com", "confirmed": true})
	}))
	mux.HandleFunc("GET /api/v2/resources", authed(func(w http.ResponseWriter, r *http.Request) {
		var out []map[string]any
		for _, s := range f.servers {
			out = append(out, map[string]any{"clientIdentifier": s, "provides": "server"})
		}
		writeJSON(w, out)
	}))
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func newTestProvider(t *testing.T, f *fakePlex) *Provider {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.newClient = func(cfg Config) *plex.Client {
		c := plex.New(cfg.ClientIdentifier(), Product)
		c.AccountBaseURL, c.ResourceBaseURL = srv.URL, srv.URL
		return c
	}
	cfg, _ := structpb.NewStruct(map[string]any{fieldMachineIdentifier: testServer})
	if err := p.Configure(context.Background(), []*pluginv1.ConfigEntry{{Key: keyServer, Value: cfg}}); err != nil {
		t.Fatal(err)
	}
	return p
}

func pinState(t *testing.T) *structpb.Struct {
	s, err := structpb.NewStruct(map[string]any{statePinID: "4242", statePinCode: testPinCode})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestInitAuthorizeCarriesStateAndPinOnForwardURL(t *testing.T) {
	p := newTestProvider(t, &fakePlex{})
	resp, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{
		RedirectUri: "https://silo.example/api/v2/auth/oauth/7/callback", State: "st",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, fragment, _ := strings.Cut(resp.GetAuthorizeUrl(), "#?")
	q, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatal(err)
	}
	forward, err := url.Parse(q.Get("forwardUrl"))
	if err != nil {
		t.Fatal(err)
	}
	if forward.Query().Get("state") != "st" || forward.Query().Get("code") != "4242" {
		t.Fatalf("forwardUrl = %s, want state=st and code=4242", forward)
	}
	if q.Get("code") != testPinCode {
		t.Fatalf("auth page PIN code = %q", q.Get("code"))
	}
	if got := resp.GetProviderState().AsMap()[statePinCode]; got != testPinCode {
		t.Fatalf("provider_state pin code = %v", got)
	}
}

func TestExchangeCode(t *testing.T) {
	cases := []struct {
		name   string
		plex   fakePlex
		code   string
		denial pluginv1.AuthDenial
	}{
		{"server shared", fakePlex{pinToken: testToken, userUUID: testUUID, servers: []string{otherServer, testServer}}, "4242", pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED},
		{"server not shared", fakePlex{pinToken: testToken, userUUID: testUUID, servers: []string{otherServer}}, "4242", pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"callback names another PIN", fakePlex{pinToken: testToken, userUUID: testUUID, servers: []string{testServer}}, "999", pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"plex.tv down", fakePlex{pinToken: testToken, userUUID: testUUID, tokenStatus: http.StatusBadGateway}, "4242", pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(t, &tc.plex)
			resp, err := p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{Code: tc.code, ProviderState: pinState(t)})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetDenial() != tc.denial {
				t.Fatalf("denial = %v (%s), want %v", resp.GetDenial(), resp.GetDenialDetail(), tc.denial)
			}
			if tc.denial != pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED {
				if resp.GetExternalSubject() != "" {
					t.Fatal("a denial must leave external_subject empty")
				}
				return
			}
			if resp.GetExternalSubject() != testUUID || resp.GetRefreshState().AsMap()[stateToken] != testToken {
				t.Fatalf("subject %q / refresh state %v", resp.GetExternalSubject(), resp.GetRefreshState().AsMap())
			}
		})
	}
}

func TestCheckAccount(t *testing.T) {
	cases := []struct {
		name    string
		plex    fakePlex
		subject string
		want    pluginv1.CheckAccountStatus
	}{
		{"still shared", fakePlex{userUUID: testUUID, servers: []string{testServer}}, testUUID, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE},
		{"share removed", fakePlex{userUUID: testUUID, servers: []string{otherServer}}, testUUID, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED},
		{"token refused", fakePlex{userUUID: testUUID, tokenStatus: http.StatusUnauthorized}, testUUID, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED},
		{"plex.tv down", fakePlex{userUUID: testUUID, tokenStatus: http.StatusServiceUnavailable}, testUUID, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE},
		{"token answers for someone else", fakePlex{userUUID: "uuid-mallory", servers: []string{testServer}}, testUUID, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(t, &tc.plex)
			state, _ := structpb.NewStruct(map[string]any{stateToken: testToken})
			resp, err := p.CheckAccount(context.Background(), &pluginv1.CheckAccountRequest{ExternalSubject: tc.subject, RefreshState: state})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetStatus() != tc.want {
				t.Fatalf("status = %v, want %v", resp.GetStatus(), tc.want)
			}
		})
	}
}
