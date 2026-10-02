import { fail, pass, reapplyFix, type CheckResult } from "./types.ts";

// Parses `apt-cache policy cloudflared`.
export function parsePolicy(text: string): { installed: string | undefined; candidate: string | undefined; installedSources: string[] } {
  const installed = /^\s*Installed:\s*(\S+)/m.exec(text)?.[1];
  const candidate = /^\s*Candidate:\s*(\S+)/m.exec(text)?.[1];
  // In the version table, version lines look like " *** 2026.9.3 500" and the source lines
  // under each look like "        500 https://pkg.cloudflare.com/cloudflared any/main amd64 Packages".
  const versionLine = /^\s*(\*\*\*\s+)?\S+\s+-?\d+\s*$/;
  const sources: string[] = [];
  let inInstalled = false;
  for (const line of text.split("\n")) {
    if (versionLine.test(line)) {
      inInstalled = /^\s*\*\*\*\s/.test(line);
      continue;
    }
    if (inInstalled && /^\s+-?\d+\s+\S/.test(line)) {
      sources.push(line.trim().replace(/^-?\d+\s+/, ""));
    }
  }
  return {
    installed: installed === "(none)" ? undefined : installed,
    candidate: candidate === "(none)" ? undefined : candidate,
    installedSources: sources,
  };
}

export function checkCloudflared(policyText: string, box: string): CheckResult {
  const name = "cloudflared from Cloudflare's apt repo";
  const policy = parsePolicy(policyText);
  if (policy.installed === undefined) {
    return fail(name, "cloudflared is not installed", reapplyFix(box));
  }
  if (!policy.installedSources.some((s) => s.includes("pkg.cloudflare.com/cloudflared"))) {
    return fail(name, `cloudflared ${policy.installed} did not come from pkg.cloudflare.com, so it will not update`, reapplyFix(box));
  }
  if (policy.candidate !== undefined && policy.candidate !== policy.installed) {
    return pass(name, `${policy.installed} installed, ${policy.candidate} available; unattended-upgrades installs it within a day`);
  }
  return pass(name, `${policy.installed}, the newest in the repo`);
}
