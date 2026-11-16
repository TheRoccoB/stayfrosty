import type { HzAction, HzFirewall, HzFirewallRule, HzServer, HzSshKey } from "./hetzner.ts";

// The cloud a box lives on. frosty's model of a server, firewall, SSH key and action is Hetzner's,
// because Hetzner came first: labels, firewalls that hold inbound rules only, actions to wait on.
// Another provider translates its own API into that model (digitalocean.ts) and keeps frosty's
// guards: every write re-reads what it changes and acts only on frosty's own resources.

export type ProviderKind = "hetzner" | "digitalocean";
export const PROVIDER_KINDS: readonly ProviderKind[] = ["hetzner", "digitalocean"];

// Hetzner firewall ids are numbers; DigitalOcean's are UUIDs.
export type FirewallId = number | string;

export type Server = Omit<HzServer, "public_net"> & {
  public_net: {
    ipv4: { ip: string } | null;
    ipv6: { ip: string } | null;
    firewalls?: { id: FirewallId; status: string }[];
  };
};

export type Firewall = Omit<HzFirewall, "id"> & { id: FirewallId };
export type FirewallRule = HzFirewallRule;
export type Action = HzAction;
export type SshKey = HzSshKey;

export interface CreateServerSpec {
  name: string;
  serverType: string;
  image: string;
  location: string;
  sshKeyIds: number[];
  userData: string;
  labels: Record<string, string>;
  firewallIds: FirewallId[];
}

export interface Provider {
  readonly kind: ProviderKind;
  // "Hetzner", "DigitalOcean": in messages such as "Hetzner firewall stayfrosty-web1".
  readonly label: string;
  // Where a person fixes by hand what frosty refuses to do: "the Hetzner Cloud Console".
  readonly consoleName: string;
  // What one token's resources are called: "Hetzner project".
  readonly accountName: string;
  // The provider's out-of-band console that the console password is for.
  readonly webConsoleName: string;

  listServers(labelSelector?: string): Promise<Server[]>;
  listFirewalls(labelSelector?: string): Promise<Firewall[]>;
  // Every server or firewall with exactly this name, frosty's or not.
  serversNamed(name: string): Promise<Server[]>;
  firewallsNamed(name: string): Promise<Firewall[]>;
  listSshKeys(): Promise<SshKey[]>;
  createSshKey(name: string, publicKey: string, labels: Record<string, string>): Promise<SshKey>;

  createFirewall(name: string, labels: Record<string, string>, rules: FirewallRule[]): Promise<{ firewall: Firewall; actions: Action[] }>;
  getFirewall(id: FirewallId): Promise<Firewall>;
  updateFirewallLabels(id: FirewallId, labels: Record<string, string>): Promise<Firewall>;
  setFirewallRules(id: FirewallId, rules: FirewallRule[]): Promise<Action[]>;
  applyFirewall(id: FirewallId, serverId: number): Promise<Action[]>;
  detachForeignFirewall(foreignId: FirewallId, serverId: number): Promise<Action[]>;
  deleteFirewall(id: FirewallId): Promise<void>;

  createServer(input: CreateServerSpec): Promise<{ server: Server; action: Action; next_actions: Action[] }>;
  updateServerLabels(id: number, labels: Record<string, string>): Promise<Server>;
  protectServer(id: number): Promise<Action>;
  getServer(id: number): Promise<Server>;
  deleteServer(id: number): Promise<Action>;
  waitForAction(action: Action, timeoutMs?: number, now?: () => number): Promise<Action>;
}

// What `new` creates a box with, from the box's provider's settings in config.
export interface ServerSettings {
  serverType: string;
  location: string;
  image: string;
}
