import { runOrFail, type SshRunner, type SshTarget } from "../box.ts";
import { checkCloudflared, checkConnector } from "./cloudflared.ts";
import { checkListeners } from "./listeners.ts";
import { checkSshd } from "./sshd.ts";
import type { CheckResult } from "./types.ts";
import { checkUfw } from "./ufw.ts";
import { checkPendingReboot, checkUnattendedUpgrades } from "./updates.ts";

// One SSH round trip collects everything; the checks themselves are pure parsers.
export const GATHER_SCRIPT = `set -u
section() { echo "### $1"; }
section sshd; sshd -T 2>&1 || true
section ufw; ufw status verbose 2>&1 || true
section ss; ss -tulnpH 2>&1 || true
section uu-enabled; systemctl is-enabled unattended-upgrades.service 2>&1 || true
section apt-config; apt-config dump 2>/dev/null | grep -E '^(Unattended-Upgrade::(Origins-Pattern|Automatic-Reboot)|APT::Periodic::(Unattended-Upgrade|Update-Package-Lists))' || true
section uu-stamp; stat -c %Y /var/lib/apt/periodic/unattended-upgrades-stamp 2>/dev/null || echo none
section reboot-required; stat -c %Y /var/run/reboot-required 2>/dev/null || echo none
section cloudflared; apt-cache policy cloudflared 2>&1 || true
section connector; systemctl is-active cloudflared.service 2>&1; systemctl is-enabled cloudflared.service 2>&1; stat -c '%a %U' /etc/cloudflared/token 2>&1 || true
section now; date +%s
section end
`;

export function parseSections(text: string): Map<string, string> {
  const out = new Map<string, string>();
  let current: string | undefined;
  let buffer: string[] = [];
  for (const line of text.split("\n")) {
    const header = /^### (\S+)$/.exec(line);
    if (header !== null) {
      if (current !== undefined) {
        out.set(current, buffer.join("\n"));
      }
      current = header[1] as string;
      buffer = [];
      continue;
    }
    buffer.push(line);
  }
  if (current !== undefined) {
    out.set(current, buffer.join("\n"));
  }
  return out;
}

export interface OnBoxExpectations {
  box: string;
  adminUser: string;
  rebootTime: string;
  createdAt: number | undefined;
  // False until the tunnel is set up (a box mid-way through `new`).
  tunnel: boolean;
}

export function evaluateOnBox(sections: Map<string, string>, want: OnBoxExpectations): CheckResult[] {
  const { box, adminUser, rebootTime, createdAt } = want;
  const get = (key: string): string => sections.get(key) ?? "";
  const now = Number(get("now").trim()) || Math.floor(Date.now() / 1000);
  return [
    checkSshd(get("sshd"), box, adminUser),
    checkUfw(get("ufw"), box),
    checkListeners(get("ss")),
    checkUnattendedUpgrades(
      { enabled: get("uu-enabled"), aptConfig: get("apt-config"), stamp: get("uu-stamp"), createdAt, now },
      box,
    ),
    checkCloudflared(get("cloudflared"), box),
    checkPendingReboot(get("reboot-required"), now, rebootTime),
    ...(want.tunnel ? [checkConnector(get("connector"), box)] : []),
  ];
}

export async function runOnBoxChecks(ssh: SshRunner, target: SshTarget, want: OnBoxExpectations): Promise<CheckResult[]> {
  const output = await runOrFail(ssh, target, "sudo bash -s", "Collecting on-box state", { stdin: GATHER_SCRIPT, timeoutMs: 60_000 });
  return evaluateOnBox(parseSections(output), want);
}
