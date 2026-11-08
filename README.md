# homelab-go

Shared Go code for the homelab services. No secrets live here — only code.

| Package | What |
|---|---|
| `infisical` | Client for a self-hosted Infisical (Universal Auth): load secrets (shared folders, then the app folder, one login), write secrets/folders, manage app identities. Go port of the Python [infisical-secret-client](https://github.com/strammermax/infisical-secret-client); same environment variables. |
| `cmd/infisical-secrets` | CLI with the same commands as the Python one (`list`, `get`, `run`, `set`, `delete`, `folder-ensure`, `identity-ensure`, `docker-login`). `run` replaces itself with the command (`exec`), so no wrapper process stays in memory. |

## Use as a library

```sh
go get github.com/strammermax/homelab-go@latest
```

```go
c, err := infisical.FromEnv(false)              // INFISICAL_ADDR, INFISICAL_CLIENT_ID, ...
secrets, err := c.LoadBundle("", nil, "")       // shared + app folder
token, err := infisical.Secret("API_TOKEN")     // env first, then Infisical (loaded once)
```

## CLI

Every release has static binaries (linux/amd64, linux/arm64, windows/amd64):

```sh
curl -fsSL -o /usr/local/bin/infisical-secrets \
  https://github.com/strammermax/homelab-go/releases/latest/download/infisical-secrets-linux-amd64
chmod +x /usr/local/bin/infisical-secrets

infisical-secrets list                              # names only, never values
infisical-secrets --path /removesky run -- ./app    # secrets only in the app's environment
printf %s "$VALUE" | infisical-secrets --admin --path /apps/x set NAME
```

Environment: `INFISICAL_ADDR`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_PROJECT_ID`,
`INFISICAL_ENVIRONMENT` (prod), `INFISICAL_SECRET_PATH` (/), `INFISICAL_SHARED_PATH`,
`INFISICAL_CA_BUNDLE`, `INFISICAL_ALLOW_HTTP`, `INFISICAL_TIMEOUT_SECONDS`;
with `--admin`: `INFISICAL_ADMIN_CLIENT_ID` / `INFISICAL_ADMIN_CLIENT_SECRET`.

## Development

```sh
go vet ./... && go test ./...
```

A push of a tag `v*` builds the binaries and publishes a GitHub release.
