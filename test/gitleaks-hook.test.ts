import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Builds fake credentials at runtime so this file never contains one.
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

function fake(length: number): string {
  const bytes = randomBytes(length);
  let out = "";
  for (const byte of bytes) {
    out += ALNUM[byte % ALNUM.length];
  }
  return out;
}

const hasGitleaks = spawnSync("gitleaks", ["version"]).status === 0;
const repoRoot = resolve(import.meta.dirname, "..");

describe.skipIf(!hasGitleaks)("pre-commit hook", () => {
  let dir = "";

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "frosty-hook-"));
    const git = (...args: string[]): void => {
      execFileSync("git", args, { cwd: dir, stdio: "ignore" });
    };
    git("init", "-q");
    git("config", "user.email", "test@example.com");
    git("config", "user.name", "test");
    git("config", "core.hooksPath", join(repoRoot, ".githooks"));
    copyFileSync(join(repoRoot, ".gitleaks.toml"), join(dir, ".gitleaks.toml"));
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function tryCommit(content: string): boolean {
    writeFileSync(join(dir, "planted.ts"), content);
    execFileSync("git", ["add", "planted.ts"], { cwd: dir });
    const result = spawnSync("git", ["commit", "-q", "-m", "planted"], { cwd: dir, encoding: "utf8" });
    if (result.status !== 0) {
      execFileSync("git", ["reset", "-q"], { cwd: dir });
    }
    return result.status === 0;
  }

  it("blocks a Hetzner token", () => {
    expect(tryCommit(`export const HCLOUD_TOKEN = "${fake(64)}";\n`)).toBe(false);
  });

  it("blocks a Cloudflare API token", () => {
    expect(tryCommit(`CLOUDFLARE_API_TOKEN=${fake(40)}\n`)).toBe(false);
  });

  it("blocks a prefixed Cloudflare token", () => {
    expect(tryCommit(`const t = "${"cf" + "at_"}${fake(44)}";\n`)).toBe(false);
  });

  it("blocks a Cloudflare tunnel token", () => {
    const token = Buffer.from(JSON.stringify({ a: fake(32), t: fake(36), s: fake(44) })).toString("base64");
    expect(tryCommit(`const t = "${token}";\n`)).toBe(false);
  });

  it("allows ordinary code", () => {
    expect(tryCommit(`export const box = "web1";\n`)).toBe(true);
  });
});
