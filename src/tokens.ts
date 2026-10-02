import type { Env } from "./config.ts";
import { FrostyError } from "./errors.ts";
import { registerSecret } from "./redact.ts";

export interface Tokens {
  hetzner: string;
  cloudflare: string;
}

export const HETZNER_TOKEN_ENV = "HCLOUD_TOKEN";
export const CLOUDFLARE_TOKEN_ENV = "CLOUDFLARE_API_TOKEN";

export const TOKEN_HELP = `Tokens are read from the environment, never from the command line or the config file.

  ${HETZNER_TOKEN_ENV}
    Hetzner Cloud Console, in a project used only for stayfrosty boxes:
    Security, API tokens, Generate API token, permission "Read & Write".
    A separate project limits what a leaked token can create or delete.

  ${CLOUDFLARE_TOKEN_ENV}
    Cloudflare dashboard, My Profile (or Manage Account), API Tokens, Create Custom Token:
      Account  Cloudflare Tunnel           Edit
      Account  Access: Apps and Policies   Edit
      Account  Notifications               Edit
      Zone     DNS                         Edit
      Zone     Zone                        Read
    Cloudflare is renaming "Edit" to "Write"; either name is the same permission.
    Account resources: only your account. Zone resources: only the one domain,
    never "All zones".

Ways to provide them without typing them into your shell history:
  op run --env-file=stayfrosty.env -- frosty <command>   (1Password)
  set -a; . ~/.config/stayfrosty/tokens.env; set +a      (a chmod 600 file)`;

export function loadTokens(env: Env = process.env): Tokens {
  const hetzner = env[HETZNER_TOKEN_ENV]?.trim() ?? "";
  const cloudflare = env[CLOUDFLARE_TOKEN_ENV]?.trim() ?? "";
  // Register before any check, so nothing below can print them.
  registerSecret(hetzner);
  registerSecret(cloudflare);
  const missing: string[] = [];
  if (hetzner.length === 0) {
    missing.push(HETZNER_TOKEN_ENV);
  }
  if (cloudflare.length === 0) {
    missing.push(CLOUDFLARE_TOKEN_ENV);
  }
  if (missing.length > 0) {
    throw new FrostyError(`Missing ${missing.join(" and ")} in the environment.`, TOKEN_HELP);
  }
  return { hetzner, cloudflare };
}
