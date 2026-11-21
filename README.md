# stayfrosty

A VPS with no front door.

`frosty` is a command-line tool that runs on your laptop. It creates a Hetzner Cloud server (or, optionally, a DigitalOcean droplet) that has no open inbound ports from its first second of life. The server is reachable only through a Cloudflare Tunnel behind Cloudflare Access, and it keeps itself patched and rebooted. `frosty` also writes your SSH config, and its `verify` command proves all of that. When the tunnel breaks, `breakglass` opens a short, narrow way back in and closes it again.

It replaces [cloudflared-vps-lockdown](https://github.com/TheRoccoB/cloudflared-vps-lockdown) (`stayfrosty.sh`).

## Status: under construction

`init`, `ls`, `new`, `destroy`, `console-password`, `adopt`, `verify` and `ssh-config` exist. `breakglass` does not yet. Do not point this at anything you care about yet.

| Milestone | What | State |
|---|---|---|
| M0 | Skeleton, CI, secret scanning, `init`, `ls` | done |
| M1 | A box that only your laptop can reach, `destroy` | done |
| M2 | Through the tunnel: Access, DNS, SSH config | done |
| M3 | `verify`, `breakglass`, `ssh-config` | `verify`, `ssh-config` done |
| M4 | `adopt`, full docs, first release | `adopt` done |
| Extra | `route`: serve a web app through the tunnel (beyond the original scope, optional) | done |
| Extra | Boxes on DigitalOcean (optional): `new`, `destroy`, `ls`, `verify`, `console-password` | done |

When it is released, it will install from a tagged version, never from `main`, and never with `curl | bash`. Test it yourself, run `verify`, and do not trust some guy on the internet.

## Tokens

`frosty` reads its tokens from the environment and nowhere else. `CLOUDFLARE_API_TOKEN` is always needed. A provider's token is needed only for commands on that provider's boxes: `HCLOUD_TOKEN` for Hetzner boxes (every box not listed as `digitalocean` in `boxProviders`), `DIGITALOCEAN_TOKEN` for DigitalOcean boxes. So a run that should only touch a DigitalOcean box can leave the Hetzner token out, and the other way round. `init` needs the Hetzner and Cloudflare tokens.

Commands over every box (`ls`, `verify --all`, `ssh-config`, and the SSH config that `new` and `destroy` rewrite) list the providers whose token is set and say which they skipped. A skipped provider's boxes are never taken for gone: `ls` doesn't call their Cloudflare side leftovers, `verify --all` says they weren't checked and exits 3, and their blocks in `~/.ssh/stayfrosty.conf` are kept as they were.

- `HCLOUD_TOKEN`: a Hetzner Cloud **Read & Write** token, in a project used only for stayfrosty boxes. One project per purpose limits what a leaked token can create or delete.
- `CLOUDFLARE_API_TOKEN`: a custom Cloudflare token with exactly these permissions. Cloudflare is renaming "Edit" to "Write", and either name is the same permission.
  - Account: Cloudflare Tunnel Edit
  - Account: Access: Apps and Policies Edit
  - Account: Notifications Edit
  - Account: Access: Service Tokens Read (only if you use `serviceTokens`, on a box or on a route)
  - Account: Access: Organizations, Identity Providers, and Groups Read (only if you use `serviceTokens`, on a box or on a route)
  - Zone (only your one domain, never all zones): DNS Edit
  - Zone (only your one domain, never all zones): Zone Read

- `DIGITALOCEAN_TOKEN` (only once the config has a `digitalocean` section, see below): a DigitalOcean token with **Custom Scopes**, an expiry (90 days is a good default), and exactly these scopes:
  - `droplet`: read, create, delete (not update, not admin)
  - `firewall`: read, create, update, delete
  - `ssh_key`: read, create
  - `tag`: read, create (not delete)
  - `actions:read`, `regions:read`, `sizes:read`, `image:read`, `snapshot:read`, `vpc:read`

  The last line is what DigitalOcean itself requires for `droplet:create`; if ticking it adds other read scopes, keep them. frosty needs no `account`, `project` or `domain` scope, and no Full Access or Read Only preset.

  **Create the token in a DigitalOcean team that holds only frosty's droplets.** DigitalOcean scopes can't be limited to some droplets: `droplet:delete` reaches every droplet in the team, and tags are the only mark of what is frosty's. frosty itself never deletes a droplet it didn't tag, but a leaked token could. A team of its own is what limits that, the way a Hetzner project of its own does.

Keep them out of your shell history. Use `op run --env-file=... -- frosty ...`, or a `chmod 600` env file that you source. Put passkeys or hardware keys on your Hetzner, DigitalOcean, Cloudflare and GitHub accounts: anyone who controls those accounts controls your boxes.

## `frosty init`

```
frosty init
```

It asks for your domain, the emails allowed through Access, an alert email, the SSH key, and the Hetzner location, server type and image. It checks both tokens with read-only calls, and writes `~/.config/stayfrosty/config.json` (mode 600). It creates nothing. Run it again to change a value; it offers your current values as defaults.

## Boxes on DigitalOcean (optional)

A box can be a DigitalOcean droplet instead of a Hetzner server, with the same cloud-init, tunnel, Access, alert, SSH config and checks. Add to the config by hand (`init` keeps these keys but doesn't ask about them):

```json
"boxProviders": { "mon1": "digitalocean" },
"digitalocean": { "region": "fra1", "size": "s-1vcpu-512mb-10gb", "image": "ubuntu-24-04-x64", "backups": false }
```

Boxes not in `boxProviders` stay on Hetzner. Then `frosty new mon1`, `destroy`, `ls`, `verify`, `ssh-config` and `console-password` work as for any box; `--type` and `--location` take DigitalOcean slugs. `backups` turns on DigitalOcean's weekly droplet backups (a paid add-on). Set `digitaloceanChangeLog` for a JSON-lines log of every DigitalOcean write.

How it maps, and what differs from Hetzner:

- **Labels are tags.** frosty's labels become the droplet tags `stayfrosty:1` and `stayfrosty-box:<box>`. frosty never changes a droplet's tags after creating it.
- **The firewall.** A DigitalOcean cloud firewall has no labels, so frosty knows its own by its whole shape: the name `stayfrosty-<box>`, applied by exactly the tag `stayfrosty-box:<box>`, exactly frosty's outbound rules, no inbound rule but the window, and attached by id only to droplets tagged `stayfrosty:1` and `stayfrosty-box:<box>`. It never writes to a firewall without that shape, and `new` refuses a box whose firewall name is taken by one. So a firewall made by hand, or one someone attached to another droplet, is left alone.
- **Outbound.** Unlike Hetzner's, a DigitalOcean firewall blocks outbound traffic that no rule allows. frosty's firewall always carries allow-all outbound rules (TCP, UDP and ICMP) and only ever changes its inbound rules: none, or the window (TCP 22 from your laptop's address).
- **Not quite from the first second.** The firewall is created before the droplet and applied by the box's tag, and attached by droplet id right after (and again by `--resume` if that attach is missing), so removing the tag by hand doesn't take it off. But DigitalOcean applies firewalls asynchronously: in a live run it reported the firewall pending for about 50 seconds after creating the droplet, 17 of them with the droplet already active. Whether traffic is filtered during that time isn't documented. Until then the droplet runs the stock image, where only sshd listens, with key-only login (DigitalOcean turns off password login when SSH keys are given). `new` waits until DigitalOcean reports the firewall applied, with nothing pending, before it connects. On Hetzner the firewall is part of the create call.
- **Deleting.** DigitalOcean deletes a firewall that still covers droplets. frosty deletes its firewall only once no droplet holds it, by id or by the box's tag, so `destroy` never leaves a droplet with no firewall.
- **No delete protection.** DigitalOcean droplets have no delete or rebuild protection. frosty refuses to delete a droplet it didn't tag, or one tagged `stayfrosty-adopted:*`, but nothing stops a person in the control panel. So `adopt` (and `detach-foreign`) refuse DigitalOcean boxes: adopting is for servers that can't be recreated, and those need protection.
- **No window age.** With no firewall labels, `ls` shows an open window on a droplet as `OPEN` without its age.
- **The droplet** gets public IPv4 and IPv6, no DigitalOcean monitoring agent and no Droplet Agent (the web Droplet Console's SSH helper). The console password is for DigitalOcean's Recovery Console.
- **IPv6.** The DNS check looks for the droplet's own IPv6 address, where on Hetzner it looks for the box's whole /64.

## `frosty adopt`

```
frosty adopt <box> --ip <ip> --host-key SHA256:... [--user root] [--resume]
```

For a server that already exists and cannot be recreated, for example one on a price that a new server would not get. It applies the same `cloud-init.yaml` as `new`, over SSH, then sets up the same tunnel, Access, alert and SSH config, closes the window and runs every check.

- The box name must be the server's name in Hetzner.
- `--host-key` is the fingerprint of the server's host key, read in the Hetzner web console with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. adopt checks it before it changes anything. `--trust-first-use` skips the check, which a man in the middle could fake.
- adopt turns on the server's delete and rebuild protection and labels it as adopted. `destroy` and `new` refuse adopted servers: frosty never deletes or recreates a server it did not create.
- If the server has a firewall frosty did not make, adopt attaches frosty's first and then stops, so you can detach the other one (Hetzner adds firewall rules together) and run it again with `--resume`.
- What it does to a running server: once the window closes all inbound stops, web ports included; UFW is reset; only the admin user can SSH; it may reboot once. The plan printed first (and `--dry-run`) says so.
- It logs in as `--user` (root by default) only to create the admin user, proves the admin user can log in and sudo, and only then hardens sshd. If anything fails it stops with the old login still working, and `--resume` picks up where it stopped.

## `frosty detach-foreign`

```
frosty detach-foreign <box> [--dry-run]
```

When adopt stops because the server has a firewall frosty did not make, this detaches that firewall from this one box, and only while frosty's own firewall is attached and applied, so the box is never left without one. The other firewall is not deleted and stays on any other servers. Then run adopt again with `--resume`.

## `frosty route` (optional)

Serve a web app on a no-front-door box. Some paths are public, and the rest sit behind Access. The app listens on `127.0.0.1` only and is reached through the box's existing tunnel, so no port opens. Every path is listed as `protected` or `public`, and every other path gets a 404 at the tunnel and never reaches the app. On protected paths, cloudflared on the box also checks the Access token itself, so a mistake at the edge still doesn't open them.

```json
"appZones": ["example.net"],
"accessTeam": "yourteam",
"routes": {
  "box1": [{
    "name": "app",
    "hostname": "app.example.net",
    "service": "http://127.0.0.1:9000",
    "protected": ["/admin", "/api"],
    "public": ["/static/", "/hooks/incoming", "/api/public/"],
    "probe": "/static/ok.txt"
  }]
}
```

- `appZones` lists the zones where route hostnames may live. It never includes frosty's own `domain`.
- `accessTeam` is your Access team name, as in `<team>.cloudflareaccess.com`.
- `probe` (optional) is a public path that answers 200 from the app. It lets `verify` tell the app apart from the tunnel's 404.
- Every entry in `protected` and `public` is a **prefix**: `/hooks/incoming` also matches `/hooks/incoming/anything`, so the app must 404 what it doesn't serve under a public prefix.
- **`publicExact`** (optional) opens single paths and nothing under or next to them: `"protected": ["/"], "publicExact": ["/api/feed"]` makes `/api/feed` public, while `/api/feed/`, `/api/feed/x` and `/api/feedx` still get the login. Each path must be inside a protected prefix of frosty's own Access app, not under a public prefix, with no trailing slash. The tunnel matches it exactly (case-sensitive). Access gets a bypass destination for the path and a `<path>/*` destination on frosty's own app, which takes the subpaths back, because Access matches a destination's path and everything under it. `verify` checks that the path reaches the app through the tunnel, and that its trailing slash, a subpath, a longer name and the upper-cased path don't: they get the login, or cloudflared's own 403 where Access's prefix match lets them past the edge. It can be the `probe`.
- **`/` covers the whole site.** `"protected": ["/"], "public": ["/health"]` puts a whole app behind Access with one open path. `"public": ["/"], "protected": ["/admin"]` is a public site with a protected part. Rules go longest prefix first and `/` last, so the more specific one always wins, and protected prefixes keep cloudflared's own Access check under a public `/`. With `/` listed there are no unlisted paths: `verify` expects the login (protected `/`) or the app (public `/`) where it would otherwise expect the tunnel's 404. `/` can't be in both lists or in `externalAccess`. Protected prefixes match case-insensitively (`/ADMIN` meets the Access check like `/admin`); public prefixes match exactly as written.

- **`serviceTokens`** (optional) lets clients that can't log in through a browser into the route's protected paths, for example monitoring agents on other machines that report to a hub on this box. Each is the name of a Cloudflare Access service token you made in the dashboard; the client sends its `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers. frosty writes one Service Auth policy, `stayfrosty-<box>:<route>:service-tokens` (one rule per named token, nothing else), and attaches it to its own Access app for the route, after the email policy. The route needs a protected prefix on frosty's own app (not `externalAccess`). As with SSH service tokens: frosty only reads tokens, never creates or rotates them; a token opens exactly one place (config refuses a name used by two routes, or by a route and a box's SSH, and `sync` refuses before any write if any other policy or app already lets it in); `plan` and `sync` print each token's expiry; `verify` fails on an expired token, a policy that lets in anything else, or a token that also opens something else. Taking the tokens out of the route detaches the policy, then deletes it. Routes without `serviceTokens` read no tokens, so they need no extra Cloudflare permission. A service token gets past Access only: the app's own login still applies.

- **`emails`** (optional) gives the route its own list of people, in place of `accessEmails`: frosty writes one allow policy, `stayfrosty-<box>:<route>:emails` (one email rule per address, nothing else), and attaches it to its own Access app for the route **instead of** the box's email policy. Use it to share one app with people who must not get into the box's SSH or its other routes. Plain addresses only (no wildcards, domains, everyone or IP rules), 1 to 50 of them, and the route needs a protected prefix on frosty's own app (not `externalAccess`). With `serviceTokens` too, the email policy comes first and the token policy last. `sync` refuses before any write if the route's email policy is attached to any other app; `verify` fails if the policy lets in anyone not on the list or leaves someone out, is on any other app, or the route's app limits its login methods. Taking `emails` out puts the box's policy back on the app first, then deletes the route's policy. The lists live in your local config only.
- **Login methods:** frosty's route apps never set `allowed_idps`, which Cloudflare reads as "every login method of the team". So people on a route's `emails` list without the team's other login (say GitHub) can use the One-time PIN, as long as One-time PIN is enabled for the team (Zero Trust, Settings, Authentication). `route sync` rewrites the whole app, so a login method limit set by hand in the dashboard doesn't survive a sync.

```json
"routes": {
  "mon1": [{
    "name": "hub",
    "hostname": "monitor.example.net",
    "service": "http://127.0.0.1:8090",
    "protected": ["/"],
    "public": [],
    "serviceTokens": ["monitoring-agents"]
  }]
}
```

Two options cover common setups:
- **A public subpath inside a protected prefix.** Here that's `/api/public/` inside `/api`. frosty gives those paths their own Access app with a bypass policy, and that is the only place it ever uses a bypass.
- **`externalAccess`.** Map protected prefixes to an Access app you already manage outside frosty, for example `"externalAccess": {"/admin": "my-app", "/api": "my-app"}`. frosty only reads that app. It must cover those paths and may only let identified people in: no everyone, IP-range or service-token rules. Map **every** protected prefix of a hostname to the same app (frosty enforces this). Two Access apps on one hostname fight over the same login cookie, and a single-page app that calls its API from the browser breaks.

Commands:
- `frosty route plan box1` shows what the routes need, including the DNS record to add for each hostname. frosty doesn't write DNS outside its own domain. It also makes the same checks of `externalAccess` apps as sync (they exist, cover the path, and only let identified people in), and exits 1 if sync would refuse.
- `frosty route sync box1` creates or updates the Access apps first, then the tunnel's ingress, and removes routes no longer in config.
- `frosty route sync box1 --dry-run` makes the same checks as sync, then prints each write sync would make, in order (Access policies and apps to create, update or delete, and the ingress rules each side of the change, `-` dropped and `+` added), and makes none: the Cloudflare client refuses every write for the run. `plan` shows the target state; the dry run shows the changes.
- `frosty verify box1` then checks every path from outside: it tries the protected paths, a set of path tricks (`..`, `%2f`, `//`, case changes) and unlisted paths, all without credentials. On the box, it checks that the app listens on 127.0.0.1 only.

See DECISIONS.md, "App routes".

## `frosty ssh-users` (optional)

```
frosty ssh-users plan <box>     print exactly what sync would change (changes nothing)
frosty ssh-users sync <box>     apply it, then check the users
```

Some boxes need a second SSH login that can only run one program, for example a home server that pulls nightly database backups. Putting that key on the admin user would make any bug in the backup program a root bug, since the admin user has passwordless sudo. A restricted user can only run its forced command. Configure them per box:

```json
"restrictedUsers": {
  "box1": [
    {
      "name": "backupuser",
      "command": "/usr/local/sbin/backup-gate",
      "groups": ["backupread"],
      "keys": ["ssh-ed25519 AAAA... backup-puller-box1"]
    }
  ]
}
```

- `name`: a lowercase Linux user name. Not root, not the admin user, not a privileged group name.
- `command`: an absolute path, letters, digits, dots, dashes and underscores only. The program itself is installed by the app that owns it. Its arguments come from the client in `SSH_ORIGINAL_COMMAND`, so it must parse them strictly.
- `groups`: the exact supplementary groups (may be empty). Never `sudo`, `admin`, `wheel`, `docker`, `adm`, `lxd`, `root`, `shadow`, `disk`, `systemd-journal`, the admin user's group or the user's own. Missing groups are created as empty system groups.
- `keys`: `ssh-ed25519` or `ecdsa-sha2-nistp*` public key lines, without options. frosty adds them.

What `sync` does on the box, as root, through the tunnel:

- a system user with shell `/bin/sh` (sshd runs a forced command through the shell, so not `nologin`), a locked password, an empty root-owned home in `/var/lib/stayfrosty/users/<name>`, and exactly the configured groups;
- `/etc/ssh/authorized_keys/<name>` (root:root 0644, in a root:root 0755 directory) with each key as `restrict,from="127.0.0.1,::1",command="<command>" <key>`;
- the sshd drop-in gets `AllowUsers <admin> <names...>` and, at the end, one `Match User <name>` block with `AuthorizedKeysFile /etc/ssh/authorized_keys/%u`, `ForceCommand <command>`, publickey only, and no TTY, forwarding of any kind, tunnels or `~/.ssh/rc`. The admin user's settings and its `~/.ssh/authorized_keys` don't change.

The drop-in is checked with `sshd -t` and the admin user's effective settings before sshd reloads, and the old file goes back if either fails. Then frosty opens a fresh admin login; if that fails it restores the old drop-in over the connection that is still open. Users taken out of config are removed (their key file, then the user) once sshd no longer lets them in. Set `boxChangeLog` to an absolute path to get a JSON line before and after each sync. `new` and `adopt` run the same sync before their final checks when the box has restricted users. With none, the drop-in is byte for byte the one in `cloud-init.yaml`.

`verify` then allows exactly the admin user plus the configured users in `AllowUsers`, and only `Match User <configured user>` blocks. For each user it reads `sshd -T -C user=<name>,...` and checks the forced command, `AuthorizedKeysFile`, and every restriction above. It also checks the user's shell, home, groups and locked password, that the key directory, key file and forced command can only be changed by root, and that every key line starts with `restrict,from="127.0.0.1,::1",command="<command>"` and matches the config. A box without `restrictedUsers` is checked exactly as before.

## `frosty service-tokens` (optional)

```
frosty service-tokens plan <box>     print exactly what sync would change (changes nothing)
frosty service-tokens sync <box>     apply it, then check the box's Access
```

An automated client on another machine, for example a backup puller, can't do the browser login that `cloudflared access ssh` normally asks for. It can use a Cloudflare Access service token instead: cloudflared reads `TUNNEL_SERVICE_TOKEN_ID` and `TUNNEL_SERVICE_TOKEN_SECRET` from the environment. Create the token yourself in the Cloudflare dashboard (Zero Trust, Access, Service credentials) and keep its secret on the client. frosty never creates, rotates or deletes tokens; it only reads their names, ids and expiry. Then name the token per box:

```json
"serviceTokens": {
  "box1": ["backup-puller-box1"]
}
```

- A token opens exactly one box. The same name under two boxes is a config error, and `sync` refuses (before any write) if any other policy or Access app already lets one of the box's tokens in: by naming it in an include or require rule, through an Access group, or by taking any valid service token (an `any_valid_service_token` rule, or a Service Auth policy for everyone). frosty reads every Access group for this and stops if a policy uses a group it can't see. Make one token per client and box.
- `sync` rewrites the box's SSH Access app, and Cloudflare resets whatever the update doesn't carry. So it refuses (before any write) when the app has other settings, such as an identity provider list, cookie or CORS settings, a custom deny page or tags, and names them.
- `sync` writes one policy, `stayfrosty-<box>:service-tokens` (decision Service Auth, one service token rule per configured token, nothing else), and then sets the box's SSH Access app to exactly its email policy plus that policy. Taking the box out of `serviceTokens` detaches the policy and then deletes it. `new` and `adopt` run the same sync before their final checks, and `destroy` deletes the policy with the box.
- `plan` and `sync` print each token's expiry, and flag a token that expires within 30 days or already has. `verify` fails on an expired token, a token policy that lets in anything else, a token that also opens another app, and a token policy left on a box with none configured.
- Reading tokens needs two more Cloudflare permissions: Account, Access: Service Tokens Read, and Account, Access: Organizations, Identity Providers, and Groups Read. Without the first, Cloudflare returns an empty list, not an error, so frosty says the token wasn't found. Without the second, frosty can't check groups and stops. Boxes without `serviceTokens` read neither, so the permissions are only needed if you use them.
- A service token gets past Access only. The client still needs an SSH key the box accepts, such as a restricted user's from `ssh-users`.

## Reboot times

`rebootTime` is the default. `rebootTimes` (an object of box name to `HH:MM`, box local time, UTC on Hetzner) gives boxes their own, so boxes that depend on each other never reboot at once. adopt and new write the box's time, and `verify` checks it.

## Change logs and guards

Set `hetznerChangeLog`, `digitaloceanChangeLog` and `cloudflareChangeLog` in the config to absolute paths, and frosty appends a JSON line before and after every API write (and `boxChangeLog` for `ssh-users sync`) (status and ids only, bodies redacted). frosty only creates, changes or deletes Cloudflare tunnels, Access apps, policies and notifications named `stayfrosty-*`, and DNS records commented `stayfrosty box *`, so a broad token cannot reach anything else through it. It never deletes a server that is adopted or protected.

## `frosty ssh-config`

```
frosty ssh-config [--dry-run]
```

Rewrites `~/.ssh/stayfrosty.conf` from the Hetzner (and DigitalOcean) API, one `Host` block per box, and adds `Include stayfrosty.conf` to the top of `~/.ssh/config` if it isn't there yet (keeping a backup). It needs both tokens, like every command, but only reads the Hetzner API. Run it after making a box from another laptop, or when the file points at a cloudflared that is gone. `new`, `adopt` and `destroy` already do this.

The `ProxyCommand` uses the first cloudflared on your `PATH`. A mise install path (`.../installs/cloudflared/<version>/...`) is written as mise's `latest` symlink to the newest installed version, so upgrading cloudflared doesn't leave SSH on the old one. Never the shim: a shim picks the version from the directory you run ssh in, so a cloned repo could choose what runs. Without a `latest` symlink (asdf), the versioned path is kept; run `frosty ssh-config` again after an upgrade.

## `frosty verify`

```
frosty verify <box>
frosty verify --all
```

Runs every check from the end of `new` and `adopt` again, through the tunnel, and changes nothing. It exits 1 when a check fails. `--all` exits 3 when every box it could check passed but it skipped a provider whose token isn't set, so a scheduled run that lost a token never reads as a pass. It also checks that frosty's firewall is the only one on the box and that an adopted box is still protected.

## Development

Requires Node 22 and [gitleaks](https://github.com/gitleaks/gitleaks).

```
npm ci
npm run hooks        # once per clone: blocks commits that contain a secret
npm test             # vitest, fake HTTP, no network
npm run typecheck
npm run frosty -- init
```

The design rules live in [DECISIONS.md](DECISIONS.md). Security configuration lives in reviewed code in this repo, and a box is never fixed by hand.

## License

MIT. See [SECURITY.md](SECURITY.md) to report a vulnerability privately.
