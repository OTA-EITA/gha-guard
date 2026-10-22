import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { formats, render } from "./report.js";
import type { Format } from "./report.js";
import { rules } from "./rules/index.js";
import { scan } from "./run.js";
import { severityRank } from "./types.js";
import type { Severity } from "./types.js";

declare const __VERSION__: string | undefined;
const version = typeof __VERSION__ === "string" ? __VERSION__ : "dev";

const usage = `usage: gha-guard [options] [path ...]

Lints GitHub Actions workflows and composite actions for security problems.
Paths default to the current directory.

options:
  --fix                 rewrite files to fix what can be fixed automatically
  --format <format>     text, json, markdown or sarif (default: text)
  --fail-on <severity>  exit 1 on findings at least this severe: high, medium, low or none (default: low)
  --list-rules          print the rules and exit
  --version             print the version and exit
  -h, --help            show this help
`;

export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  cwd: string;
}

export async function main(argv: string[], io: Io): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        fix: { type: "boolean", default: false },
        format: { type: "string", default: "text" },
        "fail-on": { type: "string", default: "low" },
        "list-rules": { type: "boolean", default: false },
        version: { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (err) {
    io.stderr(`error: ${(err as Error).message}\n\n${usage}`);
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) {
    io.stdout(usage);
    return 0;
  }
  if (values.version) {
    io.stdout(`gha-guard ${version}\n`);
    return 0;
  }
  if (values["list-rules"]) {
    io.stdout(
      rules.map((r) => `${r.id}  ${r.severity.padEnd(6)}  ${r.title}: ${r.description}`).join("\n") + "\n",
    );
    return 0;
  }
  if (!(formats as string[]).includes(values.format)) {
    io.stderr(`error: unknown format "${values.format}" (want ${formats.join(", ")})\n`);
    return 2;
  }
  const failOn = values["fail-on"];
  if (failOn !== "none" && !(failOn in severityRank)) {
    io.stderr(`error: --fail-on must be high, medium, low or none, got "${failOn}"\n`);
    return 2;
  }

  let result;
  try {
    result = await scan(positionals.length ? positionals : ["."], { fix: values.fix, cwd: io.cwd });
  } catch (err) {
    io.stderr(`error: ${(err as Error).message}\n`);
    return 2;
  }
  for (const line of result.fixed) io.stderr(`fixed ${line}\n`);
  io.stdout(render(result.findings, values.format as Format, { files: result.files, rules, version }));

  if (failOn === "none") return 0;
  const threshold = severityRank[failOn as Severity];
  return result.findings.some((f) => severityRank[f.severity] >= threshold) ? 1 : 0;
}

/**
 * Reports whether this module is the program being run. npm installs the CLI
 * behind a symlink (node_modules/.bin/gha-guard), so resolve it before comparing.
 */
export function isEntryPoint(argv1: string | undefined, moduleUrl: string): boolean {
  if (!argv1) return false;
  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

if (isEntryPoint(process.argv[1], import.meta.url)) {
  main(process.argv.slice(2), {
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
    cwd: process.cwd(),
  }).then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      process.stderr.write(`error: ${String(err)}\n`);
      process.exitCode = 2;
    },
  );
}
