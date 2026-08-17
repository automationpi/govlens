# Deploying GovLens (single image + one config file)

GovLens ships as **one container image** that runs the whole stack - the web app
plus the enabled background workers (collector, remediator, grant) - from a single
YAML config, against **your own Postgres**. GovLens never manages a database.

## 1. Prerequisites
- A Postgres database and its connection string (GovLens creates its own schema on
  first start; the DB user just needs create-table rights).
- One to three Entra service principals, depending on which modules you enable:
  - **collector** (read-only) - required for the collector module.
  - **remediator** (`roleAssignments` read+delete) - required to execute revokes.
  - **grant** (`roleAssignments` read+write) - required for self-service grants.
  - Each SP authenticates with **either a certificate or a client secret**: your choice.

## 2. Write `config.yaml`
Copy `config.example.yaml` and fill it in. Any value may use `${ENV_VAR}` to pull a
secret from the environment instead of writing it in the file, so you can keep
everything inline, everything in env, or any mix.

```yaml
database:
  dsn: "${DATABASE_URL}"                 # your Postgres
auth:
  mode: entra
  entra_tenant: <tenant-id>
  oidc_client_id: <web-app-id>
  oidc_client_secret: "${OIDC_CLIENT_SECRET}"
  redirect_url: https://govlens.example.com/auth/callback
  session_secret: "${GOVLENS_SESSION_SECRET}"
  admin_emails: [you@example.com]
service_principals:
  collector:  { app_id: <id>, cert: /secrets/collector.pem }   # cert…
  remediator: { app_id: <id>, secret: "${REMEDIATOR_SECRET}" } # …or secret
  grant:      { app_id: <id>, cert: /secrets/grant.pem,
                root_scope: /providers/Microsoft.Management/managementGroups/<mg> }
modules:
  collector:  { enabled: true, interval: 3600 }
  remediator: { enabled: true, execute: true, interval: 3600 }
  grant:      { enabled: true, execute: true, interval: 300 }
```

`cert:` may be a **file path**, an **inline PEM**, or **base64-encoded PEM**.

## 3. Run it
```bash
docker run -d --name govlens \
  -v ./config.yaml:/etc/govlens/config.yaml:ro \
  -v ./secrets:/secrets:ro \                 # only if you use cert file paths
  -e DATABASE_URL=... -e OIDC_CLIENT_SECRET=... -e GOVLENS_SESSION_SECRET=... \
  -e REMEDIATOR_SECRET=... \
  -p 8080:8080 \
  ghcr.io/automationpi/govlens
```

On start the launcher (`govlensd`) applies the schema, then supervises the web app
and each enabled worker (restarting any that exit). Logs are line-prefixed by
component (`[web]`, `[remediator]`, `[grantworker]`, `[collector]`).

## Notes
- **`execute: false`** on remediator/grant runs that worker in **dry-run** (logs what
  it would do, changes nothing) - a safe way to validate before going live.
- **Turn a module off** by `enabled: false`; its worker simply isn't started, and its
  SP credentials aren't needed.
- **Config precedence**: values interpolate `${ENV}` at load time; missing env vars
  become empty and validation will reject an incomplete config with a clear message.
- **Single component** (advanced): the image also contains `/web`, `/collect`,
  `/remediator`, `/grantworker`, `/ingest`; override the entrypoint to run just one
  (this is what the dev `docker-compose.yml` does).
- The self-service **grant module still only goes live** once its enablement gates are
  green in Admin (SP verified, catalog present, a subscription opted in) - enabling it
  here just starts the worker.
