// infisical-secrets: read secrets safely from a self-hosted Infisical.
// Same commands and options as the Python CLI (infisical_secret_client.cli):
//
//	infisical-secrets [--path P] [--environment E] [--shared-path S] [--admin] <command> ...
//	  list | get NAME | run -- CMD... | docker-login [--registry R] | set NAME (value on stdin)
//	  delete NAME | folder-ensure FOLDER | identity-ensure NAME --read P [--read P] [--write P]
//
// `run` replaces itself with the command (exec), so no wrapper process stays in memory.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/strammermax/homelab-go/infisical"
)

const usage = `gebruik: infisical-secrets [--path P] [--environment E] [--shared-path S] [--admin] <commando>
  list                 toon alleen namen, nooit waarden
  get NAAM             schrijf één secretwaarde naar stdout
  run -- CMD ...       start een proces met secrets uitsluitend in zijn environment
  docker-login [--registry R]   login bij een registry met secrets uit Infisical
  set NAAM             maak of wijzig één secret; waarde via stdin
  delete NAAM          verwijder één secret
  folder-ensure MAP    maak een map (en bovenliggende) aan
  identity-ensure NAAM --read MAP [--read MAP] [--write MAP]   app-identiteit (admin)
`

type opts struct {
	path, environment string
	sharedPath        *string
	admin             bool
	command           string
	args              []string
}

func fail(code int, format string, a ...any) int {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	return code
}

// takeOpt reads "--name value" or "--name=value" at args[i]; ok=false if args[i] is not it.
func takeOpt(args []string, i int, name string) (value string, next int, ok bool, err error) {
	a := args[i]
	if a == name {
		if i+1 >= len(args) {
			return "", i, true, fmt.Errorf("%s vereist een waarde", name)
		}
		return args[i+1], i + 2, true, nil
	}
	if strings.HasPrefix(a, name+"=") {
		return a[len(name)+1:], i + 1, true, nil
	}
	return "", i, false, nil
}

func parse(args []string) (*opts, error) {
	o := &opts{}
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		if args[i] == "-h" || args[i] == "--help" {
			return nil, errors.New("help")
		}
		if args[i] == "--admin" {
			o.admin, i = true, i+1
			continue
		}
		matched := false
		for _, name := range []string{"--path", "--environment", "--shared-path"} {
			v, next, ok, err := takeOpt(args, i, name)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			switch name {
			case "--path":
				o.path = v
			case "--environment":
				o.environment = v
			default:
				o.sharedPath = &v
			}
			i, matched = next, true
			break
		}
		if !matched {
			return nil, fmt.Errorf("onbekende optie: %s", args[i])
		}
	}
	if i >= len(args) {
		return nil, errors.New("commando ontbreekt")
	}
	o.command, o.args = args[i], args[i+1:]
	return o, nil
}

// version is set by the release build (-X main.version=YYYY.MM.DD.N).
var version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout)) }

func run(argv []string, stdin io.Reader, stdout io.Writer) int {
	if len(argv) == 1 && argv[0] == "--version" {
		fmt.Fprintln(stdout, version)
		return 0
	}
	o, err := parse(argv)
	if err != nil {
		if err.Error() == "help" {
			fmt.Fprint(stdout, usage)
			return 0
		}
		fmt.Fprint(os.Stderr, usage)
		return fail(2, "fout: %v", err)
	}
	admin := o.admin || o.command == "identity-ensure"
	client, err := infisical.FromEnv(admin)
	if err != nil {
		return fail(2, "fout: %v", err)
	}
	code, err := dispatch(client, o, stdin, stdout)
	if err != nil {
		return fail(2, "fout: %v", err)
	}
	return code
}

func oneName(o *opts) (string, error) {
	if len(o.args) != 1 || strings.HasPrefix(o.args[0], "-") {
		return "", fmt.Errorf("%s vereist precies één naam", o.command)
	}
	return o.args[0], nil
}

func dispatch(c *infisical.Client, o *opts, stdin io.Reader, stdout io.Writer) (int, error) {
	bundle := func() (map[string]string, error) { return c.LoadBundle(o.path, o.sharedPath, o.environment) }
	switch o.command {
	case "set":
		name, err := oneName(o)
		if err != nil {
			return 0, err
		}
		data, err := io.ReadAll(stdin)
		if err != nil {
			return 0, err
		}
		value := strings.TrimSuffix(string(data), "\n")
		result, err := c.SetSecret(name, value, o.path, o.environment)
		if err != nil {
			return 0, err
		}
		fmt.Fprintln(stdout, result)
		return 0, nil
	case "delete":
		name, err := oneName(o)
		if err != nil {
			return 0, err
		}
		return 0, c.DeleteSecret(name, o.path, o.environment)
	case "folder-ensure":
		name, err := oneName(o)
		if err != nil {
			return 0, err
		}
		return 0, c.EnsureFolder(name, o.environment)
	case "identity-ensure":
		return identityEnsure(c, o, stdout)
	case "list":
		s, err := bundle()
		if err != nil {
			return 0, err
		}
		names := make([]string, 0, len(s))
		for k := range s {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintln(stdout, n)
		}
		return 0, nil
	case "get":
		name, err := oneName(o)
		if err != nil {
			return 0, err
		}
		s, err := bundle()
		if err != nil {
			return 0, err
		}
		v, ok := s[name]
		if !ok {
			return 0, fmt.Errorf("secret niet gevonden: %s", name)
		}
		fmt.Fprintln(stdout, v)
		return 0, nil
	case "docker-login":
		registry := "ghcr.io"
		for i := 0; i < len(o.args); {
			v, next, ok, err := takeOpt(o.args, i, "--registry")
			if err != nil {
				return 0, err
			}
			if !ok {
				return 0, fmt.Errorf("onbekend argument: %s", o.args[i])
			}
			registry, i = v, next
		}
		s, err := bundle()
		if err != nil {
			return 0, err
		}
		user, token := s["GHCR_USERNAME"], s["GHCR_READ_TOKEN"]
		if user == "" || token == "" {
			return 0, errors.New("GHCR_USERNAME of GHCR_READ_TOKEN ontbreekt")
		}
		cmd := exec.Command("docker", "login", registry, "--username", user, "--password-stdin")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(token), os.Stdout, os.Stderr
		return exitCode(cmd.Run()), nil
	case "run":
		args := o.args
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			return 0, errors.New("run vereist een commando na --")
		}
		s, err := bundle()
		if err != nil {
			return 0, err
		}
		return runCommand(args, mergeEnv(os.Environ(), s))
	}
	return 0, fmt.Errorf("onbekend commando: %s", o.command)
}

func identityEnsure(c *infisical.Client, o *opts, stdout io.Writer) (int, error) {
	var name string
	var read, write []string
	for i := 0; i < len(o.args); {
		if v, next, ok, err := takeOpt(o.args, i, "--read"); ok || err != nil {
			if err != nil {
				return 0, err
			}
			read, i = append(read, v), next
			continue
		}
		if v, next, ok, err := takeOpt(o.args, i, "--write"); ok || err != nil {
			if err != nil {
				return 0, err
			}
			write, i = append(write, v), next
			continue
		}
		if name != "" || strings.HasPrefix(o.args[i], "-") {
			return 0, fmt.Errorf("onbekend argument: %s", o.args[i])
		}
		name, i = o.args[i], i+1
	}
	if name == "" || len(read) == 0 {
		return 0, errors.New("identity-ensure vereist een naam en minstens één --read")
	}
	id, err := c.EnsureAppIdentity(name, read, write, o.environment)
	if err != nil {
		return 0, err
	}
	fmt.Fprint(stdout, c.BootstrapEnv(id, read[len(read)-1], strings.Join(read[:len(read)-1], ",")))
	return 0, nil
}

// mergeEnv: secrets override the environment (getenv takes the first match, so no duplicates).
func mergeEnv(environ []string, secrets map[string]string) []string {
	out := make([]string, 0, len(environ)+len(secrets))
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if _, override := secrets[k]; !override {
			out = append(out, kv)
		}
	}
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+secrets[k])
	}
	return out
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 127
}
