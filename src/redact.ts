// Every API response, error and log line passes through here before it is printed.
// Three layers: exact values we know are secret (the tokens we loaded, a tunnel token we
// fetched), JSON keys that name a secret, and patterns that look like a credential.

const REDACTED = "[redacted]";

const secrets = new Set<string>();

const SECRET_KEY = /(token|secret|password|passwd|credential|private_?key|authorization|api_?key)/i;

const PATTERNS: RegExp[] = [
  // Authorization headers echoed back in errors.
  /\b(Bearer)\s+[A-Za-z0-9._~+/=-]+/gi,
  // Prefixed Cloudflare API tokens (user, account, global key).
  /\bcf(?:ut|at|k)_[A-Za-z0-9_-]{40,}/g,
  // Cloudflare tunnel tokens are base64 JSON that starts with {"a":"
  /eyJhIjoi[A-Za-z0-9+/=_-]{20,}/g,
  // Any other JWT-shaped value.
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];

export function registerSecret(value: string | undefined | null): void {
  if (value === undefined || value === null) {
    return;
  }
  const trimmed = value.trim();
  // Very short values would redact ordinary words.
  if (trimmed.length < 8) {
    return;
  }
  secrets.add(trimmed);
}

export function clearSecretsForTests(): void {
  secrets.clear();
}

export function redact(text: string): string {
  let out = text;
  // Longest first, so a secret that contains another is replaced whole.
  const known = [...secrets].sort((a, b) => b.length - a.length);
  for (const secret of known) {
    out = out.split(secret).join(REDACTED);
  }
  for (const pattern of PATTERNS) {
    out = out.replace(pattern, (match, scheme: unknown) => {
      if (typeof scheme === "string" && /^bearer$/i.test(scheme)) {
        return `${scheme} ${REDACTED}`;
      }
      return REDACTED;
    });
  }
  return out;
}

export function redactValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redact(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value)) {
      if (SECRET_KEY.test(key) && inner !== null && inner !== undefined && inner !== "") {
        out[key] = REDACTED;
      } else {
        out[key] = redactValue(inner);
      }
    }
    return out;
  }
  return value;
}

export function redactJson(value: unknown): string {
  return JSON.stringify(redactValue(value), null, 2);
}
