import { fail, pass, reapplyFix, type CheckResult } from "./types.ts";

// Parses `sshd -T`, which prints one lowercase "keyword value" per line. Keywords that can
// repeat (allowusers) collect every value.
export function parseSshdT(text: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line.length === 0) {
      continue;
    }
    const space = line.indexOf(" ");
    const key = (space === -1 ? line : line.slice(0, space)).toLowerCase();
    const value = space === -1 ? "" : line.slice(space + 1).trim();
    const list = out.get(key) ?? [];
    list.push(...(key === "allowusers" ? value.split(/\s+/) : [value]));
    out.set(key, list);
  }
  return out;
}

// `matchLines` are the Match directives in the sshd config files. `sshd -T` ignores Match
// blocks, so one could reopen root or passwords for some sources without this check seeing it.
export function checkSshd(sshdT: string, box: string, adminUser: string, matchLines = ""): CheckResult {
  const name = "sshd: keys only, no root, only the admin user";
  const values = parseSshdT(sshdT);
  if (values.size === 0) {
    return fail(name, "sshd -T printed nothing; sshd config may be invalid", reapplyFix(box));
  }
  const expected: [string, string][] = [
    ["permitrootlogin", "no"],
    ["passwordauthentication", "no"],
    ["kbdinteractiveauthentication", "no"],
    ["authenticationmethods", "publickey"],
  ];
  const wrong: string[] = [];
  for (const [key, want] of expected) {
    const got = values.get(key)?.[0];
    if (got !== want) {
      wrong.push(`${key} is ${got ?? "unset"}, want ${want}`);
    }
  }
  const allow = values.get("allowusers") ?? [];
  if (allow.length !== 1 || allow[0] !== adminUser) {
    wrong.push(`allowusers is ${allow.length === 0 ? "unset" : allow.join(" ")}, want ${adminUser}`);
  }
  const matches = matchLines.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
  if (matches.length > 0) {
    wrong.push(`the config has Match blocks (${matches.join("; ")}), which can override these`);
  }
  if (wrong.length > 0) {
    return fail(name, wrong.join("; "), reapplyFix(box));
  }
  return pass(name, `root login off, password and keyboard-interactive off, AllowUsers ${adminUser}`);
}
