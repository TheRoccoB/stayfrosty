import { createInterface, type Interface } from "node:readline/promises";
import { redact } from "./redact.ts";

// Everything a command prints or asks goes through this, so tests can capture it and
// every line is redacted on the way out.
export interface Io {
  out(line?: string): void;
  err(line?: string): void;
  ask(question: string, defaultValue?: string): Promise<string>;
  // Prints a secret a person asked for (the console password). Bypasses redaction.
  reveal(line: string): void;
  close(): void;
}

export function terminalIo(): Io {
  let rl: Interface | undefined;
  const lines: string[] = [];
  let ended = false;
  const waiters: ((line: string | undefined) => void)[] = [];
  const getRl = (): Interface => {
    if (rl === undefined) {
      rl = createInterface({ input: process.stdin, output: process.stdout, terminal: process.stdin.isTTY === true });
      rl.on("line", (line) => {
        const waiter = waiters.shift();
        if (waiter !== undefined) {
          waiter(line);
        } else {
          lines.push(line);
        }
      });
      rl.on("close", () => {
        ended = true;
        for (const waiter of waiters.splice(0)) {
          waiter(undefined);
        }
      });
    }
    return rl;
  };
  // Reads one line, from a TTY or from piped answers.
  const nextLine = (): Promise<string | undefined> => {
    getRl();
    const buffered = lines.shift();
    if (buffered !== undefined) {
      return Promise.resolve(buffered);
    }
    if (ended) {
      return Promise.resolve(undefined);
    }
    return new Promise((resolve) => waiters.push(resolve));
  };
  return {
    out(line = "") {
      process.stdout.write(`${redact(line)}\n`);
    },
    err(line = "") {
      process.stderr.write(`${redact(line)}\n`);
    },
    reveal(line) {
      process.stdout.write(`${line}\n`);
    },
    async ask(question, defaultValue) {
      const suffix = defaultValue === undefined || defaultValue === "" ? "" : ` [${defaultValue}]`;
      process.stdout.write(`${redact(question)}${suffix}: `);
      const line = await nextLine();
      if (line === undefined) {
        process.stdout.write("\n");
        if (defaultValue !== undefined) {
          return defaultValue;
        }
        return "";
      }
      if (process.stdin.isTTY !== true) {
        process.stdout.write("\n");
      }
      const answer = line.trim();
      if (answer.length === 0 && defaultValue !== undefined) {
        return defaultValue;
      }
      return answer;
    },
    close() {
      rl?.close();
    },
  };
}

const useColor = (): boolean => process.stdout.isTTY === true && process.env["NO_COLOR"] === undefined;

export function green(text: string): string {
  return useColor() ? `\u001b[32m${text}\u001b[0m` : text;
}

export function red(text: string): string {
  return useColor() ? `\u001b[31m${text}\u001b[0m` : text;
}

export function yellow(text: string): string {
  return useColor() ? `\u001b[33m${text}\u001b[0m` : text;
}

export function table(rows: string[][]): string[] {
  const widths: number[] = [];
  for (const row of rows) {
    row.forEach((cell, i) => {
      widths[i] = Math.max(widths[i] ?? 0, visibleLength(cell));
    });
  }
  return rows.map((row) =>
    row
      .map((cell, i) => (i === row.length - 1 ? cell : cell + " ".repeat((widths[i] ?? 0) - visibleLength(cell))))
      .join("  ")
      .trimEnd(),
  );
}

function visibleLength(text: string): number {
  return text.replace(/\u001b\[[0-9;]*m/g, "").length;
}
