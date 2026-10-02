import { describe, expect, it } from "vitest";
import { isPublicKey, loadTemplate, renderCloudInit } from "../src/cloudinit.ts";
import { ipv6Host } from "../src/context.ts";
import { parseTrace, windowSource } from "../src/ip.ts";

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake me@laptop";

describe("cloud-init template", () => {
  it("fills every placeholder", () => {
    const out = renderCloudInit(loadTemplate(), { adminUser: "ops", sshPublicKey: KEY, rebootTime: "03:30" });
    expect(out.startsWith("#cloud-config\n")).toBe(true);
    expect(out).toContain(`- "${KEY}"`);
    expect(out).toContain("AllowUsers ops");
    expect(out).toContain('Automatic-Reboot-Time "03:30"');
    expect(out).not.toMatch(/__[A-Z_]+__/);
  });

  it("carries no secrets and keeps the security settings", () => {
    const template = loadTemplate();
    expect(template).not.toMatch(/TUNNEL_TOKEN|HCLOUD|CLOUDFLARE_API/);
    expect(template).toContain("PermitRootLogin no");
    expect(template).toContain("PasswordAuthentication no");
    expect(template).toContain("ufw limit 22/tcp");
    expect(template).toContain('"origin=cloudflared,codename=any";');
    expect(Buffer.byteLength(template)).toBeLessThan(32 * 1024);
  });

  it("refuses values that could break out of a YAML string", () => {
    expect(isPublicKey(KEY)).toBe(true);
    expect(isPublicKey(`${KEY}"\nruncmd: [evil]`)).toBe(false);
    expect(() => renderCloudInit(loadTemplate(), { adminUser: "ops", sshPublicKey: `${KEY}"`, rebootTime: "04:00" })).toThrow(/public key/);
    expect(() => renderCloudInit(loadTemplate(), { adminUser: "root", sshPublicKey: KEY, rebootTime: "04:00" })).toThrow(/not a valid user name/);
    expect(() => renderCloudInit(loadTemplate(), { adminUser: "ops", sshPublicKey: KEY, rebootTime: "4am" })).toThrow(/04:00/);
  });
});

describe("laptop IP", () => {
  it("reads ip= from the trace", () => {
    expect(parseTrace("fl=1\nh=1.1.1.1\nip=198.51.100.7\nts=1\n")).toBe("198.51.100.7");
    expect(parseTrace("nothing")).toBeUndefined();
  });

  it("opens the window for one IPv4 address, or one IPv6 address without IPv4", () => {
    expect(windowSource({ ipv4: "198.51.100.7", ipv6: "2001:db8::5" })).toEqual({ cidr: "198.51.100.7/32", family: 4 });
    expect(windowSource({ ipv4: undefined, ipv6: "2001:db8::5" })).toEqual({ cidr: "2001:db8::5/128", family: 6 });
  });

  it("turns the box's IPv6 network into its address", () => {
    expect(ipv6Host("2001:db8:1::/64")).toBe("2001:db8:1::1");
    expect(ipv6Host(undefined)).toBeUndefined();
  });
});

describe("cloud-init failure excerpt", () => {
  it("shows the lines before the first failure, not the host keys printed after it", async () => {
    const { failureExcerpt } = await import("../src/commands/new.ts");
    const log = ["apt stuff", "Missing privilege separation directory: /run/sshd", "stayfrosty-harden: failed at line 40: sshd -t", "WARNING: Failed to run module scripts_user", "randomart"].join("\n");
    const excerpt = failureExcerpt(log, 2);
    expect(excerpt).toContain("Missing privilege separation directory");
    expect(excerpt).not.toContain("randomart");
  });

  it("falls back to the tail when there is no marker", async () => {
    const { failureExcerpt } = await import("../src/commands/new.ts");
    expect(failureExcerpt("a\nb")).toBe("a\nb");
  });
});
