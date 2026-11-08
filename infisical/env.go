package infisical

// Process-wide access to an app's secrets: one login per process, not per lookup
// (Infisical locks an identity out after a few failed logins). Without
// INFISICAL_CLIENT_ID only the environment is used.

import (
	"os"
	"regexp"
	"sync"
)

var (
	bundleMu sync.Mutex
	bundle   map[string]string
	envName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Bundle: all secrets of this app, loaded once. Empty when Infisical is not configured.
func Bundle() (map[string]string, error) {
	bundleMu.Lock()
	defer bundleMu.Unlock()
	if bundle != nil {
		return bundle, nil
	}
	if os.Getenv("INFISICAL_CLIENT_ID") == "" {
		bundle = map[string]string{}
		return bundle, nil
	}
	c, err := FromEnv(false)
	if err != nil {
		return nil, err
	}
	b, err := c.LoadBundle("", nil, "")
	if err != nil {
		return nil, err
	}
	bundle = b
	return bundle, nil
}

// Secret: the environment value if set, otherwise the Infisical value.
func Secret(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	b, err := Bundle()
	if err != nil {
		return "", err
	}
	if v, ok := b[name]; ok {
		return v, nil
	}
	return "", errorf("secret niet gevonden: %s", name)
}

// LoadIntoEnviron exports the bundle into the environment (Infisical wins over .env).
func LoadIntoEnviron() ([]string, error) {
	b, err := Bundle()
	if err != nil {
		return nil, err
	}
	var names []string
	for k, v := range b {
		if envName.MatchString(k) {
			_ = os.Setenv(k, v)
			names = append(names, k)
		}
	}
	return names, nil
}

// Reset forgets the loaded bundle (tests, or after rotating credentials).
func Reset() {
	bundleMu.Lock()
	bundle = nil
	bundleMu.Unlock()
}
