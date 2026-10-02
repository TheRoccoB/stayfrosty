import type { SshRunner, SshTarget } from "../box.ts";
import { fail, pass, type CheckResult } from "./types.ts";

// Looks for the tunnel token everywhere it must not be. The token goes in on stdin and lives
// only in a bash variable on the box; bash's printf is a builtin, so it never shows in ps.
export const TOKEN_SEARCH_SCRIPT = `token=$(cat)
pat() { printf '%s\\n' "$token"; }
echo "### ps"; ps -eo args | grep -cF -f <(pat) || true
echo "### environ"; for p in $(pgrep -x cloudflared); do tr '\\0' '\\n' < /proc/$p/environ | grep -cF -f <(pat) || true; done
echo "### files"; grep -rlsF -f <(pat) /etc /run /var /home /root /tmp /usr/local 2>/dev/null | while IFS= read -r f; do stat -c '%a %U %n' "$f"; done
echo "### end"
`;

// The places the token is meant to be, and who may own each: frosty's root-only file, and
// systemd's credential copy, which belongs to the service's dynamic user (named after the unit).
const ALLOWED: { path: RegExp; owners: string[] }[] = [
  { path: /^\/etc\/cloudflared\/token$/, owners: ["root"] },
  { path: /^\/run\/credentials\/cloudflared\.service\/tunnel-token$/, owners: ["root", "cloudflared"] },
];

export function evaluateTokenSearch(output: string): CheckResult {
  const name = "Tunnel token: not in ps, env or any readable file";
  const sections = new Map<string, string[]>();
  let current = "";
  for (const line of output.split("\n")) {
    const header = /^### (\S+)$/.exec(line);
    if (header !== null) {
      current = header[1] as string;
      sections.set(current, []);
    } else if (line.trim().length > 0) {
      sections.get(current)?.push(line.trim());
    }
  }
  const problems: string[] = [];
  // grep reads the pattern from a pipe, so a count above zero is a real process with the
  // token in its arguments.
  if ((sections.get("ps") ?? []).some((n) => Number(n) > 0)) {
    problems.push("a process has it on its command line");
  }
  if ((sections.get("environ") ?? []).some((n) => Number(n) > 0)) {
    problems.push("cloudflared has it in its environment");
  }
  for (const entry of sections.get("files") ?? []) {
    const [mode, owner, ...rest] = entry.split(" ");
    const path = rest.join(" ");
    const worldReadable = (parseInt(mode ?? "0", 8) & 0o044) !== 0;
    const allowed = ALLOWED.find((a) => a.path.test(path));
    if (allowed === undefined || worldReadable || !allowed.owners.includes(owner ?? "")) {
      problems.push(`${path} (mode ${mode}, owner ${owner})`);
    }
  }
  if (sections.get("end") === undefined) {
    problems.push("the search did not finish");
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), "Treat the token as leaked: frosty destroy the box (the tunnel and its token go with it) and create it again.");
  }
  return pass(name, `only in /etc/cloudflared/token (root, 600) and systemd's credential`);
}

export async function checkTokenNotExposed(ssh: SshRunner, target: SshTarget, token: string): Promise<CheckResult> {
  const run = await ssh(target, `sudo bash -c ${shellQuote(TOKEN_SEARCH_SCRIPT)}`, { stdin: token, timeoutMs: 120_000 });
  return evaluateTokenSearch(run.stdout);
}

function shellQuote(text: string): string {
  return `'${text.replaceAll("'", "'\\''")}'`;
}
