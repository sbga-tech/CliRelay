# CHANGELOG

## Unreleased - Purpose-built Management Provider Operations

### Breaking changes

- removed the generic `POST /v0/management/api-call` relay; callers can no longer submit arbitrary upstream methods, URLs, headers, bodies, host overrides, or stored-credential token templates
- replaced relay-backed auth-file quota reads with `GET /v0/management/auth-files/quota` and Codex reset-credit consumption with `POST /v0/management/auth-files/codex/reset-credit/consume`
- replaced relay-backed provider checks with `POST /v0/management/gemini-api-key/check`, `/claude-api-key/check`, `/codex-api-key/check`, `/vertex-api-key/check`, and `/bedrock-api-key/check`
- replaced relay-backed model discovery with `GET /v0/management/claude-api-key/models`, `/codex-api-key/models`, and `/openai-compatibility/models`; OpenCode Go catalogs now use `GET /v0/management/model-definitions/opencode-go`

### Permissions

- auth-file quota reads require `auth_files.read`
- Codex reset-credit consumption requires `auth_files.write`
- saved-provider connectivity checks and Claude, Codex, or OpenAI-compatible model discovery require `providers.test`
- OpenCode Go model definitions remain under `models.read`

### Compatibility and deployment notes

- this is a coordinated breaking deployment: first release an additive backend containing the replacement APIs and the legacy relay, then release the migrated frontend, then immediately release the final backend that removes the relay
- provider checks and model discovery accept only saved configuration indexes in the effective tenant; auth-file quota operations accept only the selected tenant auth index
- disabled saved provider rows remain testable without activation, while unsaved provider drafts must be saved before model discovery

### Verification

- focused Go coverage for auth-file quota, provider probes, config synthesis, strict model discovery, management handlers, routes, tenant scope, and permissions
- focused frontend API, quota-state, permission, latency, saved-model-discovery, and OpenCode Go tests
- Playwright coverage for quota/reset controls, provider checks, saved and unsaved discovery, permissions, and the OpenCode Go catalog
- production frontend build and repository relay-symbol scan

## v0.4.6 - OAuth Identity Fingerprints and Updater Diagnostics - 2026-06-25

### Highlights

- added account-level OAuth identity fingerprint learning and detail APIs for Claude, Codex, Gemini, and Kimi-compatible runtime flows
- added Codex OAuth client admission presets so OAuth auth files can restrict upstream access to recognized client identities
- added Claude OAuth health tracking and quota reconciliation helpers for clearer auth-file status reporting
- made updater sidecar token configuration explicit and returned health diagnostics instead of a generic unavailable state
- added quota status clear endpoints for auth-file quota and cooldown recovery workflows
- normalized OpenAI-compatible chat tool-call history and routed OpenCode Go tool-output images through vision fallback handling
- made issue triage automation command-driven for safer maintainer control

### Compatibility and upgrade notes

- direct Docker Compose deployments must provide a non-empty `CLIRELAY_UPDATER_TOKEN` shared by the API and updater sidecar
- existing identity-fingerprint configuration remains compatible; learned account records are added through runtime observation
- Codex OAuth admission uses fixed named presets rather than user-supplied matching rules
- the quota status clear endpoint is intended for management recovery flows and does not change normal quota accounting

### Verification

- `rtk go test ./...`
- `rtk git diff --check`
- PR checks for the merged `dev` pull requests
