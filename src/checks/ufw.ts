import { fail, pass, reapplyFix, type CheckResult } from "./types.ts";

const EXPECTED_RULES = ["22/tcp LIMIT IN Anywhere", "22/tcp (v6) LIMIT IN Anywhere (v6)"];

// Parses `ufw status verbose`.
export function parseUfw(text: string): { active: boolean; defaults: string; rules: string[] } {
  const lines = text.split("\n");
  const active = lines.some((l) => /^Status:\s+active/.test(l));
  const defaults = lines.find((l) => l.startsWith("Default:"))?.slice("Default:".length).trim() ?? "";
  const rules: string[] = [];
  const divider = lines.findIndex((l) => /^-+\s+-+/.test(l.trim()));
  if (divider !== -1) {
    for (const line of lines.slice(divider + 1)) {
      const normalized = line.trim().replace(/\s+/g, " ");
      if (normalized.length > 0) {
        rules.push(normalized);
      }
    }
  }
  return { active, defaults, rules };
}

export function checkUfw(text: string, box: string): CheckResult {
  const name = "UFW: deny inbound except rate-limited 22";
  const ufw = parseUfw(text);
  if (!ufw.active) {
    return fail(name, "UFW is not active", reapplyFix(box));
  }
  const problems: string[] = [];
  if (!/deny \(incoming\)/.test(ufw.defaults) || !/allow \(outgoing\)/.test(ufw.defaults)) {
    problems.push(`defaults are "${ufw.defaults}"`);
  }
  const extra = ufw.rules.filter((r) => !EXPECTED_RULES.includes(r));
  const missing = EXPECTED_RULES.filter((r) => !ufw.rules.includes(r));
  if (extra.length > 0) {
    problems.push(`unexpected rules: ${extra.join(" | ")}`);
  }
  if (missing.length > 0) {
    problems.push(`missing rules: ${missing.join(" | ")}`);
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), reapplyFix(box));
  }
  return pass(name, "active, default deny incoming, only 22/tcp LIMIT");
}
