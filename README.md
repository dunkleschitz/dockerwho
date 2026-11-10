# dockerwho

Which registry will `docker push` actually target — and which credentials will
it use — before you push.

`docker push myapp` failing with `no basic auth credentials` or `denied:
requested access to the resource is denied` is the most common docker push
failure, and the usual diagnosis is reading the push error after the fact.
dockerwho resolves an image reference to its fully-qualified form (registry,
repository, tag/digest) and reports which credential source docker will
consult for that registry — `auths` / `credHelpers` / `credsStore` — with the
config key that matched, and runs hygiene rules over the result.

## Usage

```bash
dockerwho myapp:1.0                              # resolve one image
dockerwho registry.example.com:5000/ns/app       # custom registry
dockerwho --list                                 # every registry with configured credentials
dockerwho --config ./test-config.json ubuntu     # resolve against a specific config file
dockerwho --json ubuntu                          # machine-readable report
dockerwho --version
```

Exit codes: `0` clean · `1` findings · `2` usage error / unreadable config.
`$DOCKER_CONFIG` redirects the config dir (same as docker); default
`~/.docker/config.json`.

## Example

```text
$ dockerwho myapp:1.0
dockerwho: effective push target for 'myapp:1.0'

Target:
  registry:    docker.io
  repository:  library/myapp
  tag:         1.0
  defaults:    registry:docker.io, namespace:library/ (see D05)

Config: /home/user/.docker/config.json
Credential source: auths [https://index.docker.io/v1/]
  credentials configured (identity token, canonical form); value never decoded

Findings (2):
  D04 [warning] config.json stores a base64 auth blob for 'https://index.docker.io/v1/'
  -- base64 is an encoding, not encryption; prefer a credential helper
  D05 [info] reference used implicit defaults (registry:docker.io, namespace:library/)
  -- fully-qualified form is docker.io/library/myapp:1.0; if you meant a private
  registry, qualify it explicitly
```

## Hygiene rules

| ID | Severity | What it catches |
|----|----------|-----------------|
| D01 | error | No credential source for the push registry — `docker push` will fail with an auth error (push always requires login) |
| D02 | warning | `auths` entry stored under a non-canonical key form (e.g. `docker.io` instead of `https://index.docker.io/v1/`) — docker's lookup may silently miss it |
| D03 | warning | `credsStore` is a cloud-only helper (ecr-login/gcr/…) while the target is docker.io — hub pushes will fail; use per-registry `credHelpers` |
| D04 | warning | Base64 `auth` blob in config.json — an encoding, not encryption; prefer a credential helper |
| D04b | warning | config.json readable by group/other while holding registry credentials |
| D05 | info | Implicit reference defaults applied (registry/tag/namespace) — the "pushed to docker.io, not my private registry" footgun |
| D06 | info | Empty `auths` entry — credentials are helper-managed; the entry only reserves the key |

## Model honesty

This is a static model of docker's documented credential resolution
(verified 2026-10-23 against real config examples): `credHelpers[registry]`
→ `credsStore` → `auths[canonical key]`, where Docker Hub's canonical key is
`https://index.docker.io/v1/` and other registries use their hostname as
given to `docker login`. docker itself is the final authority; a real push is
the real test. Presence of a credential source is not proof it is still
valid (tokens expire).

## Safety

- Stored credentials are **never decoded** (base64 blobs and identity tokens
  are reported by presence and kind only, never printed).
- Credential helpers are **never invoked** — reported as configured, not verified.
- No registry is ever contacted. Read-only against your own config file.

## Limitations

- Only the docker CLI config format (`~/.docker/config.json`); podman/buildah
  `auth.json` and containerd hosts.d are not modeled.
- Credentials are those of the user running dockerwho — run as the same user
  that will push (the classic "logged in as me, pushing with sudo" footgun).
- Cannot verify a credential is still valid; expiry is invisible statically.

## Pre-publish checklist

- [x] Single file, stdlib only (`dockerwho.py`)
- [x] Tests pass (25, hermetic — no docker daemon, no network, no helpers)
- [x] Secrets scan: no credential values in code/tests/docs; tool never prints them
- [x] History review: fresh local git repo
- [x] License: MIT (see LICENSE)
- [ ] Publication: pending maintainer's per-project approval
