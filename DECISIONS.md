# Decisions

One line per judgment call: what, why, and the alternative. Tagged by milestone.

## M0

- [M0] Default Hetzner location is `fsn1`, then any `eu-*` location. Why: EU locations include far more traffic (about 20 TB vs about 1 TB in the US). Alt: US default.
- [M0] Distribution is the npm package `stayfrosty` with bin `frosty`, run as `npx stayfrosty@<version>`. Why: easiest for strangers; `frosty` is taken on npm. Alt: clone the tag and `npm link`.
- [M0] Console password is printed once by default; optional `passwordCommand` receives it on stdin with `{box}` substituted. Why: no dependency on 1Password. Alt: `op` by default.
- [M0] Hetzner base URL stays `https://api.hetzner.cloud/v1`. Why: `api.hetzner.com` serves only Storage Boxes today. Alt: none.
- [M0] `init` confirms Hetzner read access only; write access is confirmed on the first write, and `token_readonly` or 403 on a write maps to a "token is read-only" hint. Why: Hetzner has no endpoint that reports a token's permissions, and init must create nothing. Alt: create and delete a throwaway resource.
- [M0] `init` checks each Cloudflare permission with a read call to its resource (DNS, tunnels, Access apps, notification policies) and says Edit/Write is confirmed on first use. Why: a token cannot read its own permission groups without also holding API Tokens Read. Alt: require API Tokens Read, which is more privilege.
- [M0] Cloudflare token verify picks the path by prefix: `cfat_` account path, `cfut_` user path, unprefixed tries user then account. Why: the two token kinds verify at different paths. Alt: always try both.
- [M0] Account ID comes from `zone.account.id` of the configured domain, not from `GET /accounts`. Why: one call gives both IDs, and token access to `/accounts` is not documented. Alt: ask for the account ID.
- [M0] A token that can see more than one zone is a warning in `init`, not a failure. Why: it works, it is just broader than needed. Alt: fail.
- [M0] Cloudflare is renaming permissions from "Edit" to "Write"; help text and checks treat them as the same. Alt: none.
- [M0] Hetzner `datacenter` is gone (2026-07-01); location comes from `server.location`. Server type availability comes from `locations[]` (`available`, `deprecation`); top-level `deprecated`/`deprecation` are still honored until they are removed. Image `deprecation` is read alongside the old `deprecated`. Alt: none.
- [M0] Default server type is the cheapest available in the location, any architecture; default image is the newest Ubuntu LTS (even `YY.04`) for that architecture. Why: smallest box, current LTS. Alt: pin x86 and a fixed LTS.
- [M0] An open window's age is stored as the firewall label `stayfrosty-window-opened=<unix seconds>`. Why: state lives in the APIs, so any laptop sees the age. Alt: a local state file.
- [M0] `ls` also lists leftovers (labeled firewalls and `stayfrosty-*` tunnels with no server). Why: so `destroy` can be proven by `ls`. Alt: a separate command.
- [M0] Zero runtime dependencies. Dev only: typescript 7, vitest 5, @types/node 22. `.npmrc` sets `ignore-scripts=true` and `save-exact=true`. Alt: an argument parser library.
- [M0] Imports use `.ts` extensions with `rewriteRelativeImportExtensions`, so `npm run frosty` runs the source with Node's type stripping and `npm run build` emits `dist/`. Alt: tsx or a bundler.
- [M0] The pre-commit hook is enabled with `npm run hooks` (sets `core.hooksPath .githooks`), not by an install script. It fails closed when gitleaks is missing. Why: no `postinstall`. Alt: husky.
- [M0] Custom gitleaks rules: Hetzner 64-character tokens next to an hcloud/hetzner name, Cloudflare 40-character tokens next to a cloudflare/CF name, prefixed `cfut_`/`cfat_`/`cfk_` tokens, and tunnel tokens (`eyJhIjoi...`). A bare 64-character string is not flagged. Why: hashes would trip it constantly. Alt: entropy-only rule.
- [M0] CI pins actions by commit SHA and the gitleaks binary by version and SHA-256, and holds no tokens. Alt: gitleaks-action.
- [M0] `LICENSE` and `SECURITY.md` ship now instead of M4. Why: the repo is public from the first push. Alt: wait for M4.
- [M0] Reads are retried on 429/502/503/504 (4 attempts, honoring Retry-After); writes are never retried. Why: a retried POST can create a duplicate. Alt: idempotency checks per write.
- [M0] Redaction has three layers: registered secret values (both tokens, later the tunnel token), JSON keys that name a secret, and patterns (Bearer, prefixed Cloudflare tokens, tunnel tokens, JWTs). Alt: key names only.

### Found while verifying the docs, for later milestones

- [M0] M1: Hetzner firewalls reject CIDRs with host bits set, so the window uses `/32` and `/128`.
- [M0] M1: poll `GET /actions/{id}`; `/<resource>/{id}/actions/{action_id}` is deprecated.
- [M0] M1: unattended-upgrades must match the cloudflared repo with `Origins-Pattern "origin=cloudflared,codename=any"`; its Release file has no Suite, so `Allowed-Origins` will not match.
- [M0] M1: CI needs `apt-get install cloud-init` before `cloud-init schema -c cloud-init.yaml`; it is not on the runner image.
- [M0] M2: `cloudflared tunnel run --token-file` exists since 2025.4.0; use it with a root-only 0600 file.
- [M0] M2: Access apps can no longer take new app-scoped policies; create a reusable policy at `/access/policies`, reference it by ID, and delete it in `destroy`.
- [M0] M2: deleting a tunnel needs `DELETE .../cfd_tunnel/{id}/connections` first.
- [M0] M2: the `tunnel_health_event` notification's `new_status` values are not documented; check `available_alerts` before filtering on them.
