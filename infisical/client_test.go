package infisical

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeInfisical: universal-auth login, v4 secrets (or only v3), folders and secret writes.
type fakeInfisical struct {
	mu       sync.Mutex
	secrets  map[string]map[string]string // path -> name -> value
	folders  map[string]bool
	logins   int
	onlyV3   bool
	requests []string
}

func newFake() *fakeInfisical {
	return &fakeInfisical{secrets: map[string]map[string]string{
		"/shared": {"A": "shared-a", "B": "shared-b"},
		"/app":    {"B": "app-b", "C": "app-c"},
	}, folders: map[string]bool{"/": true, "/shared": true, "/app": true}}
}

func (f *fakeInfisical) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	reply := func(code int, v any) { w.WriteHeader(code); _ = json.NewEncoder(w).Encode(v) }
	if r.URL.Path == "/api/v1/auth/universal-auth/login" {
		_ = r.ParseForm()
		if r.Form.Get("clientSecret") != "s3cret" {
			reply(401, map[string]any{})
			return
		}
		f.logins++
		claims := base64.RawURLEncoding.EncodeToString([]byte(`{"orgId":"org-1"}`))
		reply(200, map[string]any{"accessToken": "h." + claims + ".s"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer h."+base64.RawURLEncoding.EncodeToString([]byte(`{"orgId":"org-1"}`))+".s" {
		reply(401, map[string]any{})
		return
	}
	switch {
	case r.Method == "GET" && (r.URL.Path == "/api/v4/secrets" && !f.onlyV3 || r.URL.Path == "/api/v3/secrets/raw"):
		var list []map[string]string
		for k, v := range f.secrets[r.URL.Query().Get("secretPath")] {
			list = append(list, map[string]string{"secretKey": k, "secretValue": v})
		}
		reply(200, map[string]any{"secrets": list})
	case r.Method == "GET" && r.URL.Path == "/api/v1/folders":
		parent := r.URL.Query().Get("path")
		var out []map[string]string
		for p := range f.folders {
			if p != "/" && NormalizePath(p[:strings.LastIndex(p, "/")]) == parent {
				out = append(out, map[string]string{"name": p[strings.LastIndex(p, "/")+1:]})
			}
		}
		reply(200, map[string]any{"folders": out})
	case r.Method == "POST" && r.URL.Path == "/api/v1/folders":
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.folders[NormalizePath(b["path"]+"/"+b["name"])] = true
		reply(200, map[string]any{})
	case strings.HasPrefix(r.URL.Path, "/api/v4/secrets/"):
		name := strings.TrimPrefix(r.URL.Path, "/api/v4/secrets/")
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		path := b["secretPath"]
		_, exists := f.secrets[path][name]
		switch r.Method {
		case "PATCH":
			if !exists {
				reply(404, map[string]any{})
				return
			}
			f.secrets[path][name] = b["secretValue"]
		case "POST":
			if !f.folders[path] {
				reply(404, map[string]any{})
				return
			}
			if f.secrets[path] == nil {
				f.secrets[path] = map[string]string{}
			}
			f.secrets[path][name] = b["secretValue"]
		case "DELETE":
			delete(f.secrets[path], name)
		}
		reply(200, map[string]any{})
	default:
		reply(404, map[string]any{})
	}
}

func client(t *testing.T, f *fakeInfisical, secret string) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := New(&Config{Address: srv.URL, ClientID: "id", ClientSecret: secret, ProjectID: "p",
		SecretPath: "/app", SharedPath: "/shared", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBundleSharedThenAppOneLogin(t *testing.T) {
	f := newFake()
	b, err := client(t, f, "s3cret").LoadBundle("", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if b["A"] != "shared-a" || b["B"] != "app-b" || b["C"] != "app-c" || f.logins != 1 {
		t.Fatalf("bundle %v, logins %d", len(b), f.logins)
	}
	empty := ""
	b, _ = client(t, f, "s3cret").LoadBundle("", &empty, "")
	if _, ok := b["A"]; ok {
		t.Fatal("shared path not disabled")
	}
}

func TestV3FallbackOnlyOn404(t *testing.T) {
	f := newFake()
	f.onlyV3 = true
	if b, err := client(t, f, "s3cret").LoadBundle("", nil, ""); err != nil || b["C"] != "app-c" {
		t.Fatal(err)
	}
}

func TestLoginFailureIsSafe(t *testing.T) {
	_, err := client(t, newFake(), "wrong").LoadBundle("", nil, "")
	if err == nil || strings.Contains(err.Error(), "wrong") || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatal(err)
	}
}

func TestHTTPRefusedWithoutAllow(t *testing.T) {
	if _, err := New(&Config{Address: "http://x", ProjectID: "p"}); err == nil {
		t.Fatal("http accepted")
	}
}

func TestSetCreatesFoldersThenUpdates(t *testing.T) {
	f := newFake()
	c := client(t, f, "s3cret")
	if r, err := c.SetSecret("NEW", "v1", "/keyvault/ssh", ""); err != nil || r != "created" {
		t.Fatal(r, err)
	}
	if !f.folders["/keyvault"] || !f.folders["/keyvault/ssh"] {
		t.Fatal("folders not created")
	}
	if r, err := c.SetSecret("NEW", "v2", "/keyvault/ssh", ""); err != nil || r != "updated" || f.secrets["/keyvault/ssh"]["NEW"] != "v2" {
		t.Fatal(r, err)
	}
	if err := c.DeleteSecret("NEW", "/keyvault/ssh", ""); err != nil || len(f.secrets["/keyvault/ssh"]) != 0 {
		t.Fatal(err)
	}
}

func TestOrganizationFromToken(t *testing.T) {
	if org, err := client(t, newFake(), "s3cret").OrganizationID(); err != nil || org != "org-1" {
		t.Fatal(org, err)
	}
}

func TestNormalizePath(t *testing.T) {
	for in, want := range map[string]string{"": "/", "/": "/", "a//b/": "/a/b", "/x": "/x"} {
		if got := NormalizePath(in); got != want {
			t.Fatal(in, got)
		}
	}
}
