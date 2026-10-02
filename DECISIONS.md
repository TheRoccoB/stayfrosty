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

## M1

- [M1] The window admits the laptop's IPv4 as a /32, and frosty reaches the box on its IPv4. IPv6 (/128) is used only when the laptop has no IPv4. Why: one address, the narrowest rule. Alt: open both families.
- [M1] The laptop's public IP comes from Cloudflare's trace endpoint at 1.1.1.1 (and 2606:4700:4700::1111). Why: Cloudflare is already trusted here. Alt: a third-party "what is my IP" service.
- [M1] Console password: printed once on a terminal, or piped to `passwordCommand`, or skipped (login stays locked) with a pointer to the new `frosty console-password <box>`. `--resume` keeps an existing password. Rocco chose this. Alt: always print.
- [M1] The console password is 24 characters from 56 letters and digits without look-alikes (about 139 bits). Why: the Hetzner console types through a virtual keyboard where symbols and layouts break. Alt: symbols for more bits per character.
- [M1] The sshd drop-in adds `AuthenticationMethods publickey` to the four settings in the brief. Why: a hard guarantee that only keys work, whatever else is set. Alt: the four settings only.
- [M1] The cloudflared apt source is written by the hardening script after its key is installed, not in `write_files`. Why: cloud-init's package update runs first and would fail on a repo with no key. Alt: cloud-init `apt:` sources with the key inline.
- [M1] The Cloudflare apt key is fetched over HTTPS from pkg.cloudflare.com and not pinned by fingerprint. Why: Cloudflare rolled it in 2025, and a pin would break every new box on the next roll. Alt: pin the fingerprint in the repo.
- [M1] Hardening is files in `write_files` plus one idempotent script, `/usr/local/sbin/stayfrosty-harden`, run by `runcmd`. Only `users`, `write_files`, `packages` and `runcmd` are used. Why: `adopt` (M4) can render the same file as a script. Alt: more cloud-init modules.
- [M1] The hardening script runs `ufw --force reset` before adding its rules. Why: leftover rules (like stayfrosty.sh's home-IP rule) disappear. Alt: delete only known rules.
- [M1] frosty keeps its own `known_hosts` next to its config and trusts a new box's host key on first use, through the window. IPs are forgotten on `new` and `destroy` because Hetzner reuses them. Why: injecting host keys would put a private key in user data, which any process on the box can read. Alt: inject host keys.
- [M1] frosty runs ssh with `-F /dev/null`, so `~/.ssh/config` cannot change how it connects. A key with a passphrase must be in ssh-agent. Alt: read the user's config.
- [M1] After cloud-init, `new` reboots the box if the first upgrade asked for it, and confirms with a new boot ID. Why: a fresh box starts on its new kernel. Alt: wait for the nightly reboot.
- [M1] A cloud-init exit of 2 (recoverable errors) is a failure. Why: "finished clean" means clean. Alt: accept warnings.
- [M1] The on-box checks of section 6 plus two login checks (root refused, only publickey offered) run at the end of `new`. Their fixes say "destroy and new" until `adopt` exists. Alt: wait for `verify` in M3.
- [M1] Listening sockets allowed off loopback: TCP 22 owned by sshd or systemd (ssh.socket), UDP 68 and 546 owned by systemd-networkd (DHCP). Alt: allow nothing but 22.
- [M1] cloudflared passes when installed from pkg.cloudflare.com; a newer version in the repo is noted, not failed. Why: unattended-upgrades installs it within a day. Alt: fail on any lag, or compare with GitHub releases.
- [M1] "unattended-upgrades ran within 2 days" passes for a box younger than 2 days that has not run yet. Alt: fail new boxes until the first run.
- [M1] Box names: 1 to 30 of `a-z 0-9 -`, starting with a letter. They become the Hetzner server name and the `ssh-<box>` DNS label. Alt: allow uppercase and map it.
- [M1] The SSH public key is uploaded once as `stayfrosty-<sha256 prefix>` labeled `stayfrosty=1`, or reused if Hetzner already has it under any name. `destroy` leaves it, since boxes share it. Alt: one key per box.
- [M1] Boxes get IPv4 and IPv6. Why: GitHub and many mirrors still need IPv4. Alt: IPv6 only (later).
- [M1] `destroy` reads the typed name from stdin, so it can be piped. AGENTS.md (M3) will say an agent may do that only for test boxes it created itself. Alt: require a terminal.
- [M1] Window rules omit `destination_ips`. Why: Hetzner uses it only for outbound rules. Alt: send an empty list.
