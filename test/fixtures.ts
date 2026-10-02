import type { Config } from "../src/config.ts";
import type { Io } from "../src/io.ts";
import { redact } from "../src/redact.ts";

export const sampleConfig: Config = {
  domain: "example.com",
  accountId: "acc123",
  zoneId: "zone123",
  accessEmails: ["me@example.com"],
  alertEmail: "me@example.com",
  adminUser: "ops",
  sshKey: "~/.ssh/id_ed25519",
  location: "fsn1",
  serverType: "cx23",
  image: "ubuntu-24.04",
  rebootTime: "04:00",
  accessSessionDuration: "24h",
};

// Captures output and answers questions from a script, in order.
export class ScriptedIo implements Io {
  readonly stdout: string[] = [];
  readonly stderr: string[] = [];
  readonly questions: string[] = [];
  private readonly answers: string[];

  constructor(answers: string[] = []) {
    this.answers = [...answers];
  }

  out(line = ""): void {
    this.stdout.push(redact(line));
  }

  err(line = ""): void {
    this.stderr.push(redact(line));
  }

  async ask(question: string, defaultValue?: string): Promise<string> {
    this.questions.push(question);
    const answer = this.answers.shift();
    if (answer === undefined) {
      throw new Error(`unexpected question: ${question}`);
    }
    if (answer === "" && defaultValue !== undefined) {
      return defaultValue;
    }
    return answer;
  }

  close(): void {}

  text(): string {
    return [...this.stdout, ...this.stderr].join("\n");
  }
}
