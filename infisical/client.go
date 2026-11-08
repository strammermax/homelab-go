// Package infisical is a dependency-free client for a self-hosted Infisical (Universal Auth):
// read secrets (shared + app folder in one login), write secrets and folders, and manage
// app identities with the admin identity. Go port of the Python infisical-secret-client;
// same environment variables, endpoints and (Dutch) error texts. Errors never contain
// credentials or secret values.
package infisical

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Actions a read-only identity needs to list names and read values.
var (
	ReadActions  = []string{"describeSecret", "readValue"}
	WriteActions = []string{"create", "edit", "delete"}
)

// Error is a safe error: never contains credentials or secret values.
type Error struct {
	Msg    string
	Status int // HTTP status from Infisical, 0 when not an HTTP answer
}

func (e *Error) Error() string { return e.Msg }

func errorf(format string, a ...any) error { return &Error{Msg: fmt.Sprintf(format, a...)} }

type Config struct {
	Address      string
	ClientID     string
	ClientSecret string
	ProjectID    string
	Environment  string // default "prod"
	SecretPath   string // default "/"
	SharedPath   string // comma-separated folders, loaded before SecretPath
	AllowHTTP    bool
	CABundle     string
	Timeout      time.Duration
}

// ConfigFromEnv reads the bootstrap from the environment. With admin=true the separate
// INFISICAL_ADMIN_CLIENT_ID/SECRET are used (folders, identities, permissions).
func ConfigFromEnv(admin bool) (*Config, error) {
	required := func(name string) (string, error) {
		v := strings.TrimSpace(os.Getenv(name))
		if v == "" {
			return "", errorf("verplichte omgevingsvariabele ontbreekt: %s", name)
		}
		return v, nil
	}
	prefix := "INFISICAL_"
	if admin {
		prefix = "INFISICAL_ADMIN_"
	}
	c := &Config{Environment: envOr("INFISICAL_ENVIRONMENT", "prod"), SecretPath: envOr("INFISICAL_SECRET_PATH", "/"),
		SharedPath: os.Getenv("INFISICAL_SHARED_PATH"), CABundle: os.Getenv("INFISICAL_CA_BUNDLE")}
	var err error
	if c.Address, err = required("INFISICAL_ADDR"); err != nil {
		return nil, err
	}
	if c.ClientID, err = required(prefix + "CLIENT_ID"); err != nil {
		return nil, err
	}
	if c.ClientSecret, err = required(prefix + "CLIENT_SECRET"); err != nil {
		return nil, err
	}
	if c.ProjectID, err = required("INFISICAL_PROJECT_ID"); err != nil {
		return nil, err
	}
	switch strings.ToLower(envOr("INFISICAL_ALLOW_HTTP", "false")) {
	case "1", "true", "yes":
		c.AllowHTTP = true
	}
	secs, err := strconv.Atoi(envOr("INFISICAL_TIMEOUT_SECONDS", "15"))
	if err != nil {
		return nil, errorf("INFISICAL_TIMEOUT_SECONDS is geen getal")
	}
	c.Timeout = time.Duration(secs) * time.Second
	return c, nil
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// NormalizePath: "a//b/" -> "/a/b"; "" -> "/".
func NormalizePath(path string) string {
	var parts []string
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return "/" + strings.Join(parts, "/")
}

type Client struct {
	Config *Config
	base   string
	http   *http.Client
	mu     sync.Mutex
	token  string
}

func New(c *Config) (*Client, error) {
	base := strings.TrimRight(c.Address, "/")
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errorf("INFISICAL_ADDR moet met http:// of https:// beginnen")
	}
	if u.Scheme == "http" && !c.AllowHTTP {
		return nil, errorf("onversleuteld HTTP geweigerd; gebruik HTTPS of zet INFISICAL_ALLOW_HTTP=true")
	}
	if c.Environment == "" {
		c.Environment = "prod"
	}
	if c.SecretPath == "" {
		c.SecretPath = "/"
	}
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Second
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CABundle != "" {
		pem, err := os.ReadFile(c.CABundle)
		if err != nil {
			return nil, errorf("INFISICAL_CA_BUNDLE is niet leesbaar")
		}
		pool := x509.NewCertPool() // only this CA, like ssl.create_default_context(cafile=...)
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errorf("INFISICAL_CA_BUNDLE bevat geen certificaat")
		}
		tlsConf.RootCAs = pool
	}
	return &Client{Config: c, base: base, http: &http.Client{Timeout: c.Timeout,
		Transport: &http.Transport{TLSClientConfig: tlsConf, Proxy: http.ProxyFromEnvironment}}}, nil
}

// FromEnv = New(ConfigFromEnv(admin)).
func FromEnv(admin bool) (*Client, error) {
	c, err := ConfigFromEnv(admin)
	if err != nil {
		return nil, err
	}
	return New(c)
}

// BaseURL is the Infisical address without a trailing slash.
func (c *Client) BaseURL() string { return c.base }

func (c *Client) request(method, path string, body io.Reader, headers map[string]string, out any) error {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return errorf("ongeldig verzoek voor %s", strings.SplitN(path, "?", 2)[0])
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return errorf("Infisical is niet bereikbaar of gaf een ongeldig antwoord: %T", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return &Error{Msg: fmt.Sprintf("Infisical gaf HTTP %d voor %s", resp.StatusCode, strings.SplitN(path, "?", 2)[0]),
			Status: resp.StatusCode}
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return errorf("Infisical is niet bereikbaar of gaf een ongeldig antwoord: %T", err)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errorf("Infisical is niet bereikbaar of gaf een ongeldig antwoord: JSONDecodeError")
	}
	return nil
}

func (c *Client) api(method, path string, body any, out any) error {
	token, err := c.Login()
	if err != nil {
		return err
	}
	headers := map[string]string{"Authorization": "Bearer " + token}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		headers["Content-Type"] = "application/json"
		rd = bytes.NewReader(b)
	}
	if out == nil {
		out = &map[string]any{}
	}
	return c.request(method, path, rd, headers, out)
}

// Login returns the access token (one login per client).
func (c *Client) Login() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return c.token, nil
	}
	form := url.Values{"clientId": {c.Config.ClientID}, "clientSecret": {c.Config.ClientSecret}}.Encode()
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := c.request("POST", "/api/v1/auth/universal-auth/login", strings.NewReader(form),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", errorf("Infisical-login bevatte geen accessToken")
	}
	c.token = out.AccessToken
	return c.token, nil
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ListSecrets returns the secrets of one folder (path "" = the configured secret path).
func (c *Client) ListSecrets(path, environment string, recursive bool) (map[string]string, error) {
	token, err := c.Login()
	if err != nil {
		return nil, err
	}
	query := func(projectKey string) string {
		return url.Values{projectKey: {c.Config.ProjectID}, "environment": {or(environment, c.Config.Environment)},
			"secretPath": {or(path, c.Config.SecretPath)}, "viewSecretValue": {"true"},
			"expandSecretReferences": {"true"}, "recursive": {strconv.FormatBool(recursive)}}.Encode()
	}
	var payload struct {
		Secrets []map[string]any `json:"secrets"`
	}
	headers := map[string]string{"Authorization": "Bearer " + token}
	err = c.request("GET", "/api/v4/secrets?"+query("projectId"), nil, headers, &payload)
	// Older self-hosted releases only have the deprecated v3 route; fall back only when v4
	// itself is absent (authorization and validation failures must stay visible).
	if e, ok := err.(*Error); ok && e.Status == 404 {
		err = c.request("GET", "/api/v3/secrets/raw?"+query("workspaceId"), nil, headers, &payload)
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, item := range payload.Secrets {
		k, ok1 := item["secretKey"].(string)
		v, ok2 := item["secretValue"].(string)
		if ok1 && ok2 {
			out[k] = v
		}
	}
	return out, nil
}

func (c *Client) GetSecret(name, path, environment string) (string, error) {
	s, err := c.ListSecrets(path, environment, false)
	if err != nil {
		return "", err
	}
	v, ok := s[name]
	if !ok {
		return "", errorf("secret niet gevonden: %s", name)
	}
	return v, nil
}

// LoadBundle loads the shared folders, then the app folder (app values win), with one login.
// appPath "" = configured secret path; sharedPath nil = configured shared path ("" disables).
func (c *Client) LoadBundle(appPath string, sharedPath *string, environment string) (map[string]string, error) {
	app := or(appPath, c.Config.SecretPath)
	shared := c.Config.SharedPath
	if sharedPath != nil {
		shared = *sharedPath
	}
	result := map[string]string{}
	for _, folder := range strings.Split(shared, ",") {
		folder = strings.TrimSpace(folder)
		if folder == "" || folder == app {
			continue
		}
		s, err := c.ListSecrets(folder, environment, true)
		if err != nil {
			return nil, err
		}
		for k, v := range s {
			result[k] = v
		}
	}
	s, err := c.ListSecrets(app, environment, true)
	if err != nil {
		return nil, err
	}
	for k, v := range s {
		result[k] = v
	}
	return result, nil
}

// --- writing -----------------------------------------------------------------------------

// EnsureFolder creates every missing folder in path (no-op for "/").
func (c *Client) EnsureFolder(path, environment string) error {
	env := or(environment, c.Config.Environment)
	parent := "/"
	for _, name := range strings.Split(strings.TrimPrefix(NormalizePath(path), "/"), "/") {
		if name == "" {
			continue
		}
		q := url.Values{"workspaceId": {c.Config.ProjectID}, "environment": {env}, "path": {parent}}.Encode()
		var list struct {
			Folders []struct {
				Name string `json:"name"`
			} `json:"folders"`
		}
		if err := c.api("GET", "/api/v1/folders?"+q, nil, &list); err != nil {
			return err
		}
		exists := false
		for _, f := range list.Folders {
			if f.Name == name {
				exists = true
			}
		}
		if !exists {
			if err := c.api("POST", "/api/v1/folders", map[string]any{"workspaceId": c.Config.ProjectID,
				"environment": env, "name": name, "path": parent}, nil); err != nil {
				return err
			}
		}
		parent = NormalizePath(parent + "/" + name)
	}
	return nil
}

func status(err error) int {
	if e, ok := err.(*Error); ok {
		return e.Status
	}
	return 0
}

// SetSecret creates or updates one secret (missing folders are created). Returns "created" or "updated".
func (c *Client) SetSecret(name, value, path, environment string) (string, error) {
	p := NormalizePath(or(path, c.Config.SecretPath))
	body := map[string]any{"projectId": c.Config.ProjectID, "environment": or(environment, c.Config.Environment),
		"secretPath": p, "secretValue": value}
	quoted := url.PathEscape(name)
	err := c.api("PATCH", "/api/v4/secrets/"+quoted, body, nil)
	if err == nil {
		return "updated", nil
	}
	if s := status(err); s != 400 && s != 404 {
		return "", err
	}
	err = c.api("POST", "/api/v4/secrets/"+quoted, body, nil)
	if s := status(err); err != nil && (s == 400 || s == 404) {
		if err := c.EnsureFolder(p, environment); err != nil {
			return "", err
		}
		err = c.api("POST", "/api/v4/secrets/"+quoted, body, nil)
	}
	if err != nil {
		return "", err
	}
	return "created", nil
}

func (c *Client) DeleteSecret(name, path, environment string) error {
	return c.api("DELETE", "/api/v4/secrets/"+url.PathEscape(name), map[string]any{"projectId": c.Config.ProjectID,
		"environment": or(environment, c.Config.Environment), "secretPath": NormalizePath(or(path, c.Config.SecretPath))}, nil)
}

// --- identities (admin credentials) --------------------------------------------------------

// OrganizationID of the logged-in identity (from its access token).
func (c *Client) OrganizationID() (string, error) {
	token, err := c.Login()
	if err != nil {
		return "", err
	}
	parts := strings.Split(token, ".")
	fail := errorf("organisatie niet te bepalen uit het toegangstoken")
	if len(parts) < 2 {
		return "", fail
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", fail
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return "", fail
	}
	for _, k := range []string{"orgId", "organizationId"} {
		if s, ok := claims[k].(string); ok && s != "" {
			return s, nil
		}
	}
	return "", fail
}

func (c *Client) FindIdentity(name string) (string, error) {
	org, err := c.OrganizationID()
	if err != nil {
		return "", err
	}
	var out struct {
		IdentityMemberships []struct {
			Identity struct{ ID, Name string } `json:"identity"`
		} `json:"identityMemberships"`
	}
	if err := c.api("GET", "/api/v2/organizations/"+org+"/identity-memberships", nil, &out); err != nil {
		return "", err
	}
	for _, m := range out.IdentityMemberships {
		if m.Identity.Name == name {
			return m.Identity.ID, nil
		}
	}
	return "", nil
}

type Identity struct {
	IdentityID, ClientID, ClientSecret string
	Created                            bool
}

func pick(m map[string]any, wrapper, key string) string {
	if w, ok := m[wrapper].(map[string]any); ok {
		m = w
	}
	s, _ := m[key].(string)
	return s
}

// EnsureAppIdentity: an identity that may only read readPaths (and write writePaths). Creates
// what is missing and adds a fresh Universal Auth client secret; the caller stores it.
func (c *Client) EnsureAppIdentity(name string, readPaths, writePaths []string, environment string) (*Identity, error) {
	env := or(environment, c.Config.Environment)
	id, err := c.FindIdentity(name)
	if err != nil {
		return nil, err
	}
	created := id == ""
	if created {
		org, err := c.OrganizationID()
		if err != nil {
			return nil, err
		}
		var out map[string]any
		if err := c.api("POST", "/api/v1/identities", map[string]any{"name": name, "organizationId": org, "role": "no-access"}, &out); err != nil {
			return nil, err
		}
		if id = pick(out, "identity", "id"); id == "" {
			return nil, errorf("Infisical gaf geen identiteits-id terug")
		}
	}
	var auth map[string]any
	if err := c.api("POST", "/api/v1/auth/universal-auth/identities/"+id, map[string]any{}, &auth); err != nil {
		if status(err) != 400 { // already attached
			return nil, err
		}
		if err := c.api("GET", "/api/v1/auth/universal-auth/identities/"+id, nil, &auth); err != nil {
			return nil, err
		}
	}
	clientID := pick(auth, "identityUniversalAuth", "clientId")
	if clientID == "" {
		return nil, errorf("Infisical gaf geen client-id terug")
	}
	var sec map[string]any
	if err := c.api("POST", "/api/v1/auth/universal-auth/identities/"+id+"/client-secrets",
		map[string]any{"description": "infisical-secret-client"}, &sec); err != nil {
		return nil, err
	}
	secret, _ := sec["clientSecret"].(string)
	if secret == "" {
		return nil, errorf("Infisical gaf geen client secret terug")
	}
	if err := c.api("POST", "/api/v1/projects/"+c.Config.ProjectID+"/identity-memberships/"+id,
		map[string]any{"role": "no-access"}, nil); err != nil && status(err) != 400 { // 400: already a member
		return nil, err
	}
	if err := c.Grant(id, name, readPaths, ReadActions, env, "read"); err != nil {
		return nil, err
	}
	if len(writePaths) > 0 {
		if err := c.Grant(id, name, writePaths, append(append([]string{}, ReadActions...), WriteActions...), env, "write"); err != nil {
			return nil, err
		}
	}
	return &Identity{id, clientID, secret, created}, nil
}

// Grant: a permanent privilege on exactly these folders and their subfolders.
func (c *Client) Grant(identityID, name string, paths, actions []string, environment, kind string) error {
	var rules []any
	for _, p := range paths {
		folder := NormalizePath(p)
		patterns := map[string]bool{folder: true, strings.TrimRight(folder, "/") + "/**": true}
		keys := make([]string, 0, 2)
		for k := range patterns {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, pattern := range keys {
			rules = append(rules, map[string]any{"subject": "secrets", "action": actions,
				"conditions": map[string]any{"environment": environment, "secretPath": map[string]any{"$glob": pattern}}})
		}
	}
	slug := strings.ReplaceAll(strings.ToLower(name+"-"+kind), "_", "-")
	if len(slug) > 60 {
		slug = slug[:60]
	}
	typ := map[string]any{"isTemporary": false}
	q := url.Values{"identityId": {identityID}, "projectId": {c.Config.ProjectID}}.Encode()
	var existing struct {
		Privileges []struct{ ID, Slug string } `json:"privileges"`
	}
	// Look up first: a 400 on create also means "invalid request", not "already exists".
	if err := c.api("GET", "/api/v2/identity-project-additional-privilege?"+q, nil, &existing); err != nil {
		return err
	}
	for _, p := range existing.Privileges {
		if p.Slug == slug && p.ID != "" {
			return c.api("PATCH", "/api/v2/identity-project-additional-privilege/"+p.ID,
				map[string]any{"permissions": rules, "type": typ}, nil)
		}
	}
	return c.api("POST", "/api/v2/identity-project-additional-privilege", map[string]any{"identityId": identityID,
		"projectId": c.Config.ProjectID, "slug": slug, "permissions": rules, "type": typ}, nil)
}

// BootstrapEnv is the bootstrap file content for an app using identity (contains its secret).
func (c *Client) BootstrapEnv(id *Identity, secretPath, sharedPath string) string {
	var b strings.Builder
	line := func(k, v string) { b.WriteString(k + "=" + v + "\n") }
	line("INFISICAL_ADDR", c.base)
	line("INFISICAL_CLIENT_ID", id.ClientID)
	line("INFISICAL_CLIENT_SECRET", id.ClientSecret)
	line("INFISICAL_PROJECT_ID", c.Config.ProjectID)
	line("INFISICAL_ENVIRONMENT", c.Config.Environment)
	line("INFISICAL_SECRET_PATH", NormalizePath(secretPath))
	if sharedPath != "" {
		line("INFISICAL_SHARED_PATH", sharedPath)
	}
	if c.Config.CABundle != "" {
		line("INFISICAL_CA_BUNDLE", c.Config.CABundle)
	}
	if c.Config.AllowHTTP {
		line("INFISICAL_ALLOW_HTTP", "true")
	}
	return b.String()
}
