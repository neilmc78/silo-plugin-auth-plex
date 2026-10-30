// Package plex talks to the plex.tv account API: PIN sign-in, the signed-in
// account, and the servers that account can reach.
package plex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Default plex.tv endpoints.
const (
	DefaultAccountBaseURL  = "https://plex.tv"
	DefaultResourceBaseURL = "https://clients.plex.tv"
	DefaultAuthAppURL      = "https://app.plex.tv/auth"
)

// ErrUnauthorized means plex.tv refused the token: it was revoked, or it
// expired, and the two look the same.
var ErrUnauthorized = errors.New("plex.tv refused the token")

// ErrNotFound means plex.tv does not know the PIN, usually because it expired.
var ErrNotFound = errors.New("plex.tv does not know this PIN")

// Client calls plex.tv as one Plex client (X-Plex-Client-Identifier). A PIN can
// only be read back by the client identifier that created it.
type Client struct {
	HTTP             *http.Client
	ClientIdentifier string
	Product          string
	AccountBaseURL   string
	ResourceBaseURL  string
	AuthAppURL       string
}

// New returns a client for the real plex.tv.
func New(clientIdentifier, product string) *Client {
	return &Client{
		HTTP:             &http.Client{Timeout: 15 * time.Second},
		ClientIdentifier: clientIdentifier,
		Product:          product,
		AccountBaseURL:   DefaultAccountBaseURL,
		ResourceBaseURL:  DefaultResourceBaseURL,
		AuthAppURL:       DefaultAuthAppURL,
	}
}

// Pin is a plex.tv sign-in PIN. AuthToken is empty until the person approves it.
type Pin struct {
	ID        int64  `json:"id"`
	Code      string `json:"code"`
	AuthToken string `json:"authToken"`
}

// User is the signed-in plex.tv account.
type User struct {
	ID        int64  `json:"id"`
	UUID      string `json:"uuid"`
	Username  string `json:"username"`
	Title     string `json:"title"`
	Email     string `json:"email"`
	Thumb     string `json:"thumb"`
	Confirmed *bool  `json:"confirmed"`
}

// Resource is a device the account can reach, such as a Plex Media Server.
type Resource struct {
	Name             string `json:"name"`
	ClientIdentifier string `json:"clientIdentifier"`
	Provides         string `json:"provides"`
	Owned            bool   `json:"owned"`
}

// CreatePin starts a strong (long-code) PIN for the browser sign-in flow.
func (c *Client) CreatePin(ctx context.Context) (Pin, error) {
	var pin Pin
	err := c.do(ctx, http.MethodPost, c.AccountBaseURL+"/api/v2/pins?strong=true", "", &pin)
	if err == nil && (pin.ID == 0 || pin.Code == "") {
		err = errors.New("plex.tv returned a PIN without an id or code")
	}
	return pin, err
}

// GetPin reads a PIN back. Plex only answers the client that created it and
// only with the PIN's code.
func (c *Client) GetPin(ctx context.Context, id int64, code string) (Pin, error) {
	var pin Pin
	endpoint := c.AccountBaseURL + "/api/v2/pins/" + strconv.FormatInt(id, 10) + "?code=" + url.QueryEscape(code)
	err := c.do(ctx, http.MethodGet, endpoint, "", &pin)
	return pin, err
}

// AuthURL is the Plex sign-in page for a PIN. Plex sends the browser to
// forwardURL once the person approves it.
func (c *Client) AuthURL(pinCode, forwardURL string) string {
	q := url.Values{}
	q.Set("clientID", c.ClientIdentifier)
	q.Set("code", pinCode)
	q.Set("forwardUrl", forwardURL)
	q.Set("context[device][product]", c.Product)
	// Plex reads these parameters from the fragment, not the query.
	return c.AuthAppURL + "#?" + q.Encode()
}

// User returns the account the token belongs to.
func (c *Client) User(ctx context.Context, token string) (User, error) {
	var user User
	err := c.do(ctx, http.MethodGet, c.AccountBaseURL+"/api/v2/user", token, &user)
	if err == nil && user.UUID == "" {
		err = errors.New("plex.tv returned an account without a uuid")
	}
	return user, err
}

// Resources lists the devices the account can reach, including servers shared
// with it.
func (c *Client) Resources(ctx context.Context, token string) ([]Resource, error) {
	var resources []Resource
	err := c.do(ctx, http.MethodGet, c.ResourceBaseURL+"/api/v2/resources?includeHttps=1", token, &resources)
	return resources, err
}

// HasServer reports whether resources include the server with this machine
// identifier.
func HasServer(resources []Resource, machineIdentifier string) (Resource, bool) {
	for _, r := range resources {
		if r.ClientIdentifier == machineIdentifier {
			return r, true
		}
	}
	return Resource{}, false
}

func (c *Client) do(ctx context.Context, method, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Client-Identifier", c.ClientIdentifier)
	req.Header.Set("X-Plex-Product", c.Product)
	if token != "" {
		req.Header.Set("X-Plex-Token", token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		// The body is not echoed: it can carry account details.
		return fmt.Errorf("plex.tv answered %s %s with HTTP %d", method, redact(endpoint), resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode plex.tv response: %w", err)
	}
	return nil
}

// redact drops the query, which can hold a PIN code.
func redact(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "plex.tv"
	}
	u.RawQuery = ""
	return u.String()
}
