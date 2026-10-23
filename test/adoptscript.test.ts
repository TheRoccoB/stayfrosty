import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { hardenScript, parseCloudInit, userScript } from "../src/adoptscript.ts";
import { loadTemplate, renderCloudInit } from "../src/cloudinit.ts";

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake me@laptop";
const rendered = (): string => renderCloudInit(loadTemplate(), { adminUser: "ops", sshPublicKey: KEY, rebootTime: "04:00" });

const hasPyYaml = spawnSync("python3", ["-I", "-c", "import yaml"]).status === 0;

describe("adopt's reading of cloud-init.yaml", () => {
  it.skipIf(!hasPyYaml)("matches what a real YAML parser reads from the shipped template", () => {
    const text = rendered();
    const yaml = JSON.parse(
      execFileSync("python3", ["-I", "-c", "import json,sys,yaml; print(json.dumps(yaml.safe_load(sys.stdin.read())))"], { input: text }).toString(),
    ) as Record<string, unknown>;
    const plan = parseCloudInit(text);
    expect(plan.packages).toEqual(yaml["packages"]);
    expect(plan.runcmd).toEqual((yaml["runcmd"] as string[][]).map((c) => c[0]));
    expect(plan.files).toEqual(yaml["write_files"]);
    expect(Object.keys(yaml).sort()).toEqual(["disable_root", "package_update", "package_upgrade", "packages", "runcmd", "ssh_pwauth", "users", "write_files"]);
    // userScript makes the same user cloud-init would.
    expect(yaml["users"]).toEqual([
      { name: "ops", groups: ["sudo"], shell: "/bin/bash", sudo: "ALL=(ALL) NOPASSWD:ALL", lock_passwd: true, ssh_authorized_keys: [KEY] },
    ]);
  });

  it("finds every file the hardening needs", () => {
    const plan = parseCloudInit(rendered());
    expect(plan.files.map((f) => f.path)).toEqual([
      "/etc/ssh/sshd_config.d/00-stayfrosty.conf",
      "/etc/apt/apt.conf.d/20auto-upgrades",
      "/etc/apt/apt.conf.d/52stayfrosty-unattended-upgrades",
      "/etc/systemd/system/cloudflared.service",
      "/usr/local/sbin/stayfrosty-harden",
    ]);
    expect(plan.files[0]?.content).toContain("AllowUsers ops\n");
    expect(plan.runcmd).toEqual(["/usr/local/sbin/stayfrosty-harden"]);
  });

  const refuses = (text: string, what: RegExp): void => {
    expect(() => parseCloudInit(text)).toThrow(what);
  };

  it("refuses keys and shapes it does not know, so the template cannot drift past adopt", () => {
    const text = rendered();
    refuses(text.replace("runcmd:", "bootcmd:\n  - [echo]\nruncmd:"), /bootcmd/);
    refuses(text.replace("package_upgrade: true", "package_upgrade: false"), /package_upgrade is false/);
    refuses(text.replace('permissions: "0644"', 'permissions: "644"'), /permissions/);
    refuses(text.replace("content: |", "content: >"), /not a \| block/);
    refuses(text.replace("  - path: /etc/apt/apt.conf.d/20auto-upgrades", "  - path: /etc/../root/x"), /path/);
    refuses(text.replace("  - ufw\n", "  - ufw; rm -rf /\n"), /list line|package/);
    refuses(text.replace("#cloud-config", "#cloud-config\n\tfoo: 1"), /tab/);
    refuses(text.replace("runcmd:\n  - [/usr/local/sbin/stayfrosty-harden]", "runcmd:\n  - [/bin/sh, -c, x]"), /runcmd/);
    refuses(text.replace("write_files:", "write_files:\n  - path: /etc/x\n    encoding: b64\n    content: |\n      x"), /without owner|write_files line/);
    refuses(text.replace(/^packages:[\s\S]*?(?=^write_files:)/m, ""), /no packages/);
  });

  it("builds a phase-2 script that bash accepts and that writes the files byte for byte", () => {
    const plan = parseCloudInit(rendered());
    const script = hardenScript(plan);
    expect(spawnSync("bash", ["-n"], { input: script }).status).toBe(0);
    // Run only the file-writing part, rooted in a temp dir, and compare.
    const root = mkdtempSync(join(tmpdir(), "frosty-adopt-"));
    try {
      const files = script
        .split("\n")
        .filter((l) => /^(install -d|printf '%s' '|mv ')/.test(l))
        .map((l) => l.replaceAll("'/", `'${root}/`).replace('"$(dirname \'', `"$(dirname '`))
        .join("\n");
      const r = spawnSync("bash", ["-euo", "pipefail", "-c", files]);
      expect(r.status, r.stderr.toString()).toBe(0);
      for (const f of plan.files) {
        expect(execFileSync("cat", [join(root, f.path)]).toString()).toBe(f.content);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
    expect(script.indexOf("apt-get \"${apt_opts[@]}\" install ufw")).toBeLessThan(script.indexOf("/etc/ssh/sshd_config.d/00-stayfrosty.conf"));
    expect(script.trimEnd().split("\n").slice(-2)).toEqual(["/usr/local/sbin/stayfrosty-harden", "echo stayfrosty-harden-ok"]);
  });

  it("builds a phase-1 script that creates the user without touching sshd", () => {
    const script = userScript("ops", KEY);
    expect(spawnSync("bash", ["-n"], { input: script }).status).toBe(0);
    expect(script).not.toMatch(/sshd|ufw|systemctl/);
    expect(script).toContain("visudo -cqf");
    expect(script).not.toContain(KEY);
    // Any comment character is safe: the key is decoded on the box.
    const odd = userScript("ops", `${KEY.split(" ").slice(0, 2).join(" ")} it's $(touch x) \`y\``);
    expect(spawnSync("bash", ["-n"], { input: odd }).status).toBe(0);
    expect(() => userScript("root", KEY)).toThrow(/not a valid user name/);
    expect(() => userScript("ops; rm", KEY)).toThrow(/not a valid user name/);
  });

  it("decodes the key on the box exactly", () => {
    const dir = mkdtempSync(join(tmpdir(), "frosty-key-"));
    try {
      const odd = `${KEY.split(" ").slice(0, 2).join(" ")} it's $(touch ${dir}/pwned)`;
      const decode = userScript("ops", odd).split("\n").find((l) => l.startsWith("key=")) as string;
      writeFileSync(join(dir, "s.sh"), `${decode}\nprintf '%s' "$key"`);
      expect(execFileSync("bash", [join(dir, "s.sh")]).toString()).toBe(odd);
      expect(spawnSync("test", ["-e", join(dir, "pwned")]).status).not.toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
