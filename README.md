# stayfrosty

A VPS with no front door.

`frosty` is a command-line tool that runs on your laptop. It creates a Hetzner Cloud server that has no open inbound ports from its first second of life. The server is reachable only through a Cloudflare Tunnel behind Cloudflare Access, and it keeps itself patched and rebooted. `frosty` also writes your SSH config, and its `verify` command proves all of that. When the tunnel breaks, `breakglass` opens a short, narrow way back in and closes it again.

It replaces [cloudflared-vps-lockdown](https://github.com/TheRoccoB/cloudflared-vps-lockdown) (`stayfrosty.sh`).

## Status: under construction

`init`, `ls`, `new`, `destroy`, `console-password`, `adopt` and `verify` exist. `breakglass` and `ssh-config` do not yet. Do not point this at anything you care about yet.

| Milestone | What | State |
|---|---|---|
| M0 | Skeleton, CI, secret scanning, `init`, `ls` | done |
| M1 | A box that only your laptop can reach, `destroy` | done |
| M2 | Through the tunnel: Access, DNS, SSH config | done |
| M3 | `verify`, `breakglass`, `ssh-config` | `verify` done |
| M4 | `adopt`, full docs, first release | `adopt` done |

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

## Change logs and guards

Set `hetznerChangeLog` and `cloudflareChangeLog` in the config to absolute paths, and frosty appends a JSON line before and after every API write (status and ids only, bodies redacted). frosty only creates, changes or deletes Cloudflare tunnels, Access apps, policies and notifications named `stayfrosty-*`, and DNS records commented `stayfrosty box *`, so a broad token cannot reach anything else through it. It never deletes a server that is adopted or protected.

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
