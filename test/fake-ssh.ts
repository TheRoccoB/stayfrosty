import type { SshResult, SshRunOptions, SshTarget } from "../src/box.ts";
import { GATHER_SCRIPT } from "../src/checks/onbox.ts";
import { TOKEN_SEARCH_SCRIPT } from "../src/checks/token.ts";
import { APT_CONFIG_GOOD, POLICY_GOOD, SS_GOOD, SSHD_T_GOOD, UFW_GOOD } from "./box-fixtures.ts";

export interface SshCall {
  target: SshTarget;
  command: string;
  opts: SshRunOptions;
}

type Responder = (call: SshCall) => SshResult | undefined;

const ok = (stdout = ""): SshResult => ({ code: 0, stdout, stderr: "" });

// A box that behaves like a freshly hardened one. Tests override single commands.
export class FakeBox {
  readonly calls: SshCall[] = [];
  private readonly overrides: Responder[] = [];
  passwordState = "L";
  rebootRequired = false;
  bootId = "boot-1";

  on(responder: Responder): this {
    this.overrides.unshift(responder);
    return this;
  }

  readonly run = async (target: SshTarget, command: string, opts: SshRunOptions = {}): Promise<SshResult> => {
    const call = { target, command, opts };
    this.calls.push(call);
    for (const responder of this.overrides) {
      const result = responder(call);
      if (result !== undefined) {
        return result;
      }
    }
    if (target.user === "root") {
      return { code: 255, stdout: "", stderr: "root@192.0.2.10: Permission denied (publickey).\n" };
    }
    if (opts.extraOptions?.includes("PreferredAuthentications=none") === true) {
      return { code: 255, stdout: "", stderr: "debug1: Authentications that can continue: publickey\nPermission denied (publickey).\n" };
    }
    if (command === "sudo bash -s" && opts.stdin === GATHER_SCRIPT) {
      return ok(gatherOutput());
    }
    if (command.startsWith("sudo bash -c") && command.includes(TOKEN_SEARCH_SCRIPT.split("\n")[0] as string)) {
      return ok("### ps\n0\n### environ\n0\n### files\n600 root /etc/cloudflared/token\n400 root /run/credentials/cloudflared.service/tunnel-token\n### end\n");
    }
    if (command.startsWith("sudo passwd -S")) {
      return ok(`ops ${this.passwordState} 2026-10-01 0 99999 7 -1\n`);
    }
    if (command === "sudo chpasswd") {
      this.passwordState = "P";
      return ok();
    }
    if (command.startsWith("test -f /var/run/reboot-required")) {
      return ok(this.rebootRequired ? `${this.bootId}\n` : "");
    }
    if (command === "sudo systemctl reboot") {
      this.rebootRequired = false;
      this.bootId = "boot-2";
      return { code: 255, stdout: "", stderr: "Connection closed by remote host\n" };
    }
    if (command === "cat /proc/sys/kernel/random/boot_id") {
      return ok(`${this.bootId}\n`);
    }
    return ok();
  };

  commands(): string[] {
    return this.calls.map((c) => c.command);
  }
}

export function gatherOutput(now = Math.floor(Date.now() / 1000)): string {
  return [
    "### sshd", SSHD_T_GOOD,
    "### ufw", UFW_GOOD,
    "### ss", SS_GOOD,
    "### uu-enabled", "enabled",
    "### apt-config", APT_CONFIG_GOOD,
    "### uu-stamp", "none",
    "### reboot-required", "none",
    "### cloudflared", POLICY_GOOD,
    "### connector", "active\nenabled\n600 root",
    "### now", String(now),
    "### end",
  ].join("\n");
}
