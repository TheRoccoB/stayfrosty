import { fail, pass, reapplyFix, type CheckResult } from "./types.ts";

const DAY = 86_400;

function ageText(seconds: number): string {
  if (seconds < 3600) {
    return `${Math.max(0, Math.floor(seconds / 60))}m`;
  }
  if (seconds < 2 * DAY) {
    return `${Math.floor(seconds / 3600)}h`;
  }
  return `${Math.floor(seconds / DAY)}d`;
}

export function parseEpoch(text: string | undefined): number | undefined {
  const value = Number((text ?? "").trim());
  return Number.isFinite(value) && value > 0 ? value : undefined;
}

export interface UpdatesInput {
  enabled: string;
  aptConfig: string;
  stamp: string | undefined;
  // When the box was created, from the Hetzner API. The image ships with stamps from the day
  // it was built, so a stamp older than the box means it has not run on this box yet.
  createdAt: number | undefined;
  now: number;
}

export function checkUnattendedUpgrades(input: UpdatesInput, box: string): CheckResult {
  const name = "unattended-upgrades: on, cloudflared included, auto reboot";
  const problems: string[] = [];
  if (input.enabled.trim() !== "enabled") {
    problems.push(`service is ${input.enabled.trim() || "missing"}`);
  }
  if (!/^APT::Periodic::Unattended-Upgrade "1";/m.test(input.aptConfig)) {
    problems.push("APT::Periodic::Unattended-Upgrade is not 1");
  }
  if (!/^Unattended-Upgrade::Origins-Pattern:: "origin=cloudflared,codename=any";/m.test(input.aptConfig)) {
    problems.push("the cloudflared origin is not allowed");
  }
  if (!/^Unattended-Upgrade::Origins-Pattern:: "origin=\$\{distro_id\},archive=\$\{distro_codename\}-security";/m.test(input.aptConfig)) {
    problems.push("the Ubuntu security origin is not allowed");
  }
  if (!/^Unattended-Upgrade::Automatic-Reboot "true";/m.test(input.aptConfig)) {
    problems.push("automatic reboot is off");
  }
  const born = input.createdAt;
  const rawStamp = parseEpoch(input.stamp);
  const stamp = rawStamp !== undefined && born !== undefined && rawStamp < born ? undefined : rawStamp;
  if (stamp === undefined) {
    if (born === undefined || input.now - born > 2 * DAY) {
      problems.push("it has never run on this box");
    }
  } else if (input.now - stamp > 2 * DAY) {
    problems.push(`last run ${ageText(input.now - stamp)} ago`);
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), reapplyFix(box));
  }
  const last = stamp === undefined ? "not run yet (new box)" : `last run ${ageText(input.now - stamp)} ago`;
  return pass(name, last);
}

export function checkPendingReboot(rebootRequired: string | undefined, now: number, rebootTime: string): CheckResult {
  const name = "No reboot pending for more than 2 days";
  const since = parseEpoch(rebootRequired);
  if (since === undefined) {
    return pass(name, "no reboot pending");
  }
  const age = now - since;
  if (age > 2 * DAY) {
    return fail(name, `a reboot has been pending for ${ageText(age)}, so automatic reboot is not working`, "Reboot it now (sudo reboot), then check /var/log/unattended-upgrades/ for why it did not.");
  }
  return pass(name, `reboot pending for ${ageText(age)}; it reboots itself at ${rebootTime}`);
}
