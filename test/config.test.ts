import { mkdtempSync, rmSync, statSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { configPath, loadConfig, saveConfig, validateConfig } from "../src/config.ts";
import { sampleConfig } from "./fixtures.ts";

describe("config", () => {
  let home = "";

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "frosty-config-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("uses XDG_CONFIG_HOME when set", () => {
    expect(configPath({ HOME: "/h", XDG_CONFIG_HOME: "/x" })).toBe("/x/stayfrosty/config.json");
    expect(configPath({ HOME: "/h" })).toBe("/h/.config/stayfrosty/config.json");
  });

  it("writes 0600 in a 0700 directory and reads it back", async () => {
    const env = { HOME: home };
    const path = await saveConfig(sampleConfig, env);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(join(home, ".config", "stayfrosty")).mode & 0o777).toBe(0o700);
    expect(await loadConfig(env)).toEqual(sampleConfig);
  });

  it("warns when the file is readable by others", async () => {
    const env = { HOME: home };
    const path = await saveConfig(sampleConfig, env);
    chmodSync(path, 0o644);
    const warnings: string[] = [];
    await loadConfig(env, (line) => warnings.push(line));
    expect(warnings.join("\n")).toContain("chmod 600");
  });

  it("explains a missing config with the next command", async () => {
    await expect(loadConfig({ HOME: home })).rejects.toMatchObject({ hint: "Run: frosty init" });
  });

  it("rejects invalid JSON with a fix", async () => {
    mkdirSync(join(home, ".config", "stayfrosty"), { recursive: true });
    writeFileSync(join(home, ".config", "stayfrosty", "config.json"), "{nope");
    await expect(loadConfig({ HOME: home })).rejects.toThrow(/not valid JSON/);
  });

  it("validates fields", () => {
    expect(validateConfig(sampleConfig)).toEqual([]);
    const bad = { ...sampleConfig, adminUser: "root", accessEmails: ["nope"], rebootTime: "4am", domain: "Example" };
    const problems = validateConfig(bad);
    expect(problems).toHaveLength(4);
    expect(validateConfig([])).toEqual(["the file is not a JSON object"]);
  });
});
