import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { isAdminUser, isRebootTime } from "./config.ts";
import { FrostyError } from "./errors.ts";

export interface CloudInitValues {
  adminUser: string;
  sshPublicKey: string;
  rebootTime: string;
}

// The template ships next to dist/ and src/, at the package root.
export function templatePath(): string {
  return fileURLToPath(new URL("../cloud-init.yaml", import.meta.url));
}

export function loadTemplate(): string {
  return readFileSync(templatePath(), "utf8");
}

const PUBLIC_KEY = /^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}( [^"\\\r\n]*)?$/;

export function isPublicKey(value: string): boolean {
  return PUBLIC_KEY.test(value);
}

// Values land inside double-quoted YAML strings and config files, so each is validated
// against a pattern that cannot contain a quote, backslash or newline.
export function renderCloudInit(template: string, values: CloudInitValues): string {
  if (!isAdminUser(values.adminUser)) {
    throw new FrostyError(`Admin user "${values.adminUser}" is not a valid user name.`, "Fix adminUser with: frosty init");
  }
  if (!isPublicKey(values.sshPublicKey)) {
    throw new FrostyError("The SSH public key does not look like a single OpenSSH public key line.", "Check the .pub file next to sshKey in your config, or run: frosty init");
  }
  if (!isRebootTime(values.rebootTime)) {
    throw new FrostyError(`Reboot time "${values.rebootTime}" must look like 04:00.`, "Fix rebootTime with: frosty init");
  }
  const out = template
    .replaceAll("__ADMIN_USER__", values.adminUser)
    .replaceAll("__SSH_PUBLIC_KEY__", values.sshPublicKey)
    .replaceAll("__REBOOT_TIME__", values.rebootTime);
  const leftover = /__[A-Z_]+__/.exec(out);
  if (leftover !== null) {
    throw new FrostyError(`cloud-init.yaml has a placeholder frosty does not fill: ${leftover[0]}.`, "This is a bug in frosty. Please report it.");
  }
  return out;
}
