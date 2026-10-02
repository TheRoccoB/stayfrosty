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

### Found in the live runs

- [M1] Ubuntu 26.04 starts sshd through socket activation, so `/run/sshd` does not exist until the first connection and `sshd -t` fails without it. The hardening script creates it first. Alt: start ssh.service first.
- [M1] UFW's `limit 22/tcp` rejects an IP after 6 new connections in 30 seconds, and frosty's own commands tripped it. frosty now shares one SSH connection per box (ControlMaster, 60s persist, socket next to the config), and its connection polls run every 10 seconds instead of 5. The login checks and post-reboot polls open fresh connections on purpose. Alt: `allow 22/tcp` instead of `limit`.
- [M1] The Hetzner Ubuntu image ships with an unattended-upgrades stamp from the day it was built, and `boot-finished` changes on every boot. The "ran within 2 days" check uses the server's `created` time from the API and ignores stamps older than the box. Alt: a marker file written by cloud-init.
- [M1] When cloud-init fails, `new` shows the log lines before the first failure marker, not the last lines (which are host keys), and the hardening script reports the failing line through an ERR trap. Alt: dump the whole log.
- [M1] In fsn1 the cheapest type Hetzner offers today is cpx12, so that is the default `init` picks. Alt: none; it comes from the API.
- [M1] Acceptance: Rocco skipped the hotspot scan. From the laptop, only IPv4 port 22 answered (the window), and nothing answered on the box's IPv6, including 22. The console password worked in the Hetzner web console.
- [M1] `init` lists sold-out server types (Hetzner's `locations[].available: false`) with where they are still in stock, but refuses them as a choice. Why: the cheap cx and cax types were sold out everywhere, so `init` defaulted to cpx12 at twice the price and nothing said why. Rocco asked for this. Alt: hide them.

## M2

- [M2] cloudflared runs from a unit in `cloud-init.yaml` (no secret in it), as a systemd `DynamicUser` with hardening options. The token reaches it as a systemd credential (`LoadCredential`, `--token-file %d/tunnel-token`), so it is never on a command line or in an environment, and cloudflared itself is not root. Why: tighter than Cloudflare's own unit, which runs as root with `--token-file /etc/cloudflared/token`. Alt: Cloudflare's unit.
- [M2] `Restart=always` and `--no-autoupdate`. There is no `cloudflared-update` timer: apt and unattended-upgrades update it. Alt: Cloudflare's update timer.
- [M2] frosty writes the token over SSH on stdin to `/etc/cloudflared/token` (root, 600, in a 700 directory), then enables and restarts the unit. Alt: `cloudflared service install <token>`, which puts it on the command line.
- [M2] Access: a reusable `allow` policy for `accessEmails`, referenced by ID from a `self_hosted` app for the SSH hostname, `app_launcher_visible: false`, all identity providers allowed. Why: Cloudflare no longer takes new app-scoped policies, and `self_hosted` is what `cloudflared access ssh` uses. Alt: the `infrastructure` type, which needs WARP.
- [M2] The tunnel alert filters on the tunnel ID only, not `new_status` (its values are undocumented), so it also emails when the tunnel recovers. Alt: discover statuses at runtime.
- [M2] Cloudflare has no labels: tunnels, Access apps, Access policies and alerts are frosty's by the name `stayfrosty-<box>`, and the DNS record by the comment `stayfrosty box <box>` (record tags need a paid plan). A record at the SSH hostname without that comment stops `new`. Alt: tags.
- [M2] `destroy` deletes in this order: alert, Access app, Access policy, DNS, server, firewall, then tunnel (after dropping its connections). Why: no tunnel-down email when the box goes, and a policy cannot be deleted while an app uses it. Alt: none.
- [M2] Host keys are pinned per box under `HostKeyAlias stayfrosty-<box>` in frosty's known_hosts, learned through the window. The tunnel path uses `StrictHostKeyChecking yes`, so it must present the same key. This replaces M1's per-IP entries. Alt: trust on first use over the tunnel.
- [M2] `~/.ssh/stayfrosty.conf` is rewritten whole from the labeled Hetzner servers on every `new` and `destroy`. `Include stayfrosty.conf` goes at the top of `~/.ssh/config` once, after a timestamped backup. The ProxyCommand uses the absolute path of `cloudflared` found on PATH. Alt: edit `~/.ssh/config` directly.
- [M2] Step 14 runs the real `ssh <box> true` through the user's config, in BatchMode, and passes cloudflared's messages through so the login URL shows if no browser opens. frosty warns first when `cloudflared access token` says no login is cached. Note: that URL carries a one-time transfer token; it is printed because the user may need it. Alt: redact it.
- [M2] Before anything on the laptop looks up a new SSH hostname, frosty waits until the zone's own nameservers answer for it, then until the system resolver does (with a flush hint after 60s). Why: the first live run looked it up seconds too early, and macOS cached "no such host" for the zone's 30-minute negative TTL. Alt: retry for 30 minutes.
- [M2] `--resume` reopens the window for the current IP and closes it again at the end. Why: every resumed step runs through the window, and step 15 is the one place it closes. Alt: resume through the tunnel when it works.
- [M2] `console-password` goes through the tunnel by default; `--direct` uses the box's IP during an open window. Alt: always direct.
- [M2] The Access check accepts a redirect to `*.cloudflareaccess.com/cdn-cgi/access/login/` or a 401 with `WWW-Authenticate` (Cloudflare's opt-in managed OAuth). Alt: redirect only.
- [M2] The DNS leak check flags any record in the zone that contains the box's IPv4 or points into its IPv6 /64. Alt: exact addresses only.
- [M2] The token check searches `ps`, cloudflared's environment, and `/etc /run /var /home /root /tmp /usr/local`. On the box the token lives only in a bash variable and reaches grep through a pipe. Allowed: `/etc/cloudflared/token` (root:root 600) and systemd's credential (root:root 440 plus an ACL for the service user), seen on the live box. Alt: check the two files only.
- [M2] Listening sockets: cloudflared's outbound QUIC connections (UDP, unconnected, on ports 32768 and up) are expected. Any TCP listener of cloudflared's off loopback still fails. Seen on the live box: 4 sockets. Alt: allow cloudflared on any port.
- [M2] `passwordCommand` recipe for 1Password, set in Rocco's config: `jq -R '{category: "PASSWORD", fields: [{id: "password", type: "CONCEALED", purpose: "PASSWORD", label: "password", value: .}]}' | op item create --title 'stayfrosty {box} console (ops)' - >/dev/null`. `op item create -` reads the item JSON from stdin, so the password is never an argument, and op's own output is dropped. Goes in the README at M4. Alt: `pbcopy`.
- [M2] `destroy` does not touch the 1Password item; frosty never knows where a password went. Alt: a `passwordDeleteCommand`.
- [M2] Acceptance: `ssh t1` through Access worked after one browser login; the window closed; the box IP answered nothing from the laptop; all 16 checks passed through the tunnel; `destroy` removed all 7 resources and `ls` was empty.
