# stayfrosty

A VPS with no front door.

`frosty` is a command-line tool that runs on your laptop. It creates a Hetzner Cloud server that has no open inbound ports from its first second of life. The server is reachable only through a Cloudflare Tunnel behind Cloudflare Access, and it keeps itself patched and rebooted. `frosty` also writes your SSH config, and its `verify` command proves all of that. When the tunnel breaks, `breakglass` opens a short, narrow way back in and closes it again.

It replaces [cloudflared-vps-lockdown](https://github.com/TheRoccoB/cloudflared-vps-lockdown) (`stayfrosty.sh`).

## Status: under construction

This is milestone M0. Only `frosty init` and `frosty ls` exist. The commands that create boxes come in the next milestones. Do not point this at anything you care about yet.

| Milestone | What | State |
|---|---|---|
| M0 | Skeleton, CI, secret scanning, `init`, `ls` | done |
| M1 | A box that only your laptop can reach, `destroy` | next |
| M2 | Through the tunnel: Access, DNS, SSH config | |
| M3 | `verify`, `breakglass`, `ssh-config` | |
| M4 | `adopt`, full docs, first release | |

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
