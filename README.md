# stayfrosty

A VPS with no front door.

`frosty` is a command-line tool that runs on your laptop. It creates a Hetzner Cloud server that has no open inbound ports from its first second of life. The server is reachable only through a Cloudflare Tunnel behind Cloudflare Access, and it keeps itself patched and rebooted. `frosty` also writes your SSH config, and its `verify` command proves all of that. When the tunnel breaks, `breakglass` opens a short, narrow way back in and closes it again.

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

When it is released, it will install from a tagged version, never from `main`, and never with `curl | bash`. Test it yourself, run `verify`, and do not trust some guy on the internet.

## Tokens

`frosty` reads two tokens from the environment and nowhere else.

- `HCLOUD_TOKEN`: a Hetzner Cloud **Read & Write** token, in a project used only for stayfrosty boxes. One project per purpose limits what a leaked token can create or delete.
- `CLOUDFLARE_API_TOKEN`: a custom Cloudflare token with exactly these permissions. Cloudflare is renaming "Edit" to "Write", and either name is the same permission.
  - Account: Cloudflare Tunnel Edit
  - Account: Access: Apps and Policies Edit
  - Account: Notifications Edit
  - Zone (only your one domain, never all zones): DNS Edit
  - Zone (only your one domain, never all zones): Zone Read

Keep them out of your shell history. Use `op run --env-file=... -- frosty ...`, or a `chmod 600` env file that you source. Put passkeys or hardware keys on your Hetzner, Cloudflare and GitHub accounts: anyone who controls those accounts controls your boxes.

## `frosty init`

```
frosty init
```

It asks for your domain, the emails allowed through Access, an alert email, the SSH key, and the Hetzner location, server type and image. It checks both tokens with read-only calls, and writes `~/.config/stayfrosty/config.json` (mode 600). It creates nothing. Run it again to change a value; it offers your current values as defaults.

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

Two options cover common setups:
- **A public subpath inside a protected prefix.** Here that's `/api/public/` inside `/api`. frosty gives those paths their own Access app with a bypass policy, and that is the only place it ever uses a bypass.
- **`externalAccess`.** Map protected prefixes to an Access app you already manage outside frosty, for example `"externalAccess": {"/admin": "my-app", "/api": "my-app"}`. frosty only reads that app. It must cover those paths and may only let identified people in: no everyone, IP-range or service-token rules. Map **every** protected prefix of a hostname to the same app (frosty enforces this). Two Access apps on one hostname fight over the same login cookie, and a single-page app that calls its API from the browser breaks.

Commands:
- `frosty route plan box1` shows what the routes need, including the DNS record to add for each hostname. frosty doesn't write DNS outside its own domain.
- `frosty route sync box1` creates or updates the Access apps first, then the tunnel's ingress, and removes routes no longer in config.
- `frosty verify box1` then checks every path from outside: it tries the protected paths, a set of path tricks (`..`, `%2f`, `//`, case changes) and unlisted paths, all without credentials. On the box, it checks that the app listens on 127.0.0.1 only.

See DECISIONS.md, "App routes".

## Reboot times

`rebootTime` is the default. `rebootTimes` (an object of box name to `HH:MM`, box local time, UTC on Hetzner) gives boxes their own, so boxes that depend on each other never reboot at once. adopt and new write the box's time, and `verify` checks it.

## Change logs and guards

Set `hetznerChangeLog` and `cloudflareChangeLog` in the config to absolute paths, and frosty appends a JSON line before and after every API write (status and ids only, bodies redacted). frosty only creates, changes or deletes Cloudflare tunnels, Access apps, policies and notifications named `stayfrosty-*`, and DNS records commented `stayfrosty box *`, so a broad token cannot reach anything else through it. It never deletes a server that is adopted or protected.

## `frosty ssh-config`

```
frosty ssh-config [--dry-run]
```

Rewrites `~/.ssh/stayfrosty.conf` from the Hetzner API, one `Host` block per box. Run it after making a box from another laptop, or when the file points at a cloudflared that is gone. `new`, `adopt` and `destroy` already do this.

The `ProxyCommand` uses the first cloudflared on your `PATH`. A version manager's versioned path (mise or asdf, `.../installs/cloudflared/<version>/`) is swapped for its shim, so upgrading cloudflared doesn't leave SSH on the old version.

## `frosty verify`

```
frosty verify <box>
frosty verify --all
```

Runs every check from the end of `new` and `adopt` again, through the tunnel, and changes nothing. It also checks that frosty's firewall is the only one on the box and that an adopted box is still protected.

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
