import { cpSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { main } from "../src/cli.js";

const fixtures = fileURLToPath(new URL("./fixtures/", import.meta.url));

async function cli(args: string[], cwd = fixtures) {
  let stdout = "";
  let stderr = "";
  const code = await main(args, { stdout: (s) => (stdout += s), stderr: (s) => (stderr += s), cwd });
  return { code, stdout, stderr };
}

describe("cli", () => {
  it("reports findings with relative paths and exits 1", async () => {
    const r = await cli([path.join(fixtures, "vulnerable")]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("vulnerable/.github/workflows/triage.yml:10  HIGH   GHA002");
    expect(r.stdout).toContain("vulnerable/actions/notify/action.yml:6:");
    expect(r.stdout).toContain("4 file(s)");
  });

  it("reports a file that cannot be parsed as GHA000 and keeps scanning the others", async () => {
    const r = await cli(["--format", "json", path.join(fixtures, "broken")]);
    expect(r.code).toBe(1);
    const findings = (JSON.parse(r.stdout) as { findings: { ruleId: string; file: string; line: number }[] })
      .findings;
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "GHA000",
        file: "broken/.github/workflows/duplicate-key.yml",
        line: 8,
        message: "could not parse the file, so it was not checked: Map keys must be unique",
      }),
    );
    expect(findings).toContainEqual(
      expect.objectContaining({ ruleId: "GHA001", file: "broken/.github/workflows/valid.yml" }),
    );
  });

  it("looks up workflow_run upstreams among the scanned workflows of the same directory", async () => {
    const dir = path.join(fixtures, "exposure/.github/workflows");
    const all = await cli(["--fail-on", "none", path.join(fixtures, "exposure")]);
    expect(all.stdout).toContain("exposure/.github/workflows/pwn-workflow-run.yml:10  MEDIUM GHA002");
    // Scanned alone, the upstream is unknown, so the finding stays high.
    const alone = await cli(["--fail-on", "none", path.join(dir, "pwn-workflow-run.yml")]);
    expect(alone.stdout).toContain("pwn-workflow-run.yml:10  HIGH   GHA002");
  });

  it("passes a clean repository", async () => {
    const r = await cli([path.join(fixtures, "clean")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("1 file(s), 0 finding(s)");
  });

  it("honours --fail-on", async () => {
    const vulnerable = path.join(fixtures, "vulnerable");
    expect((await cli(["--fail-on", "none", vulnerable])).code).toBe(0);
    expect((await cli(["--fail-on", "high", path.join(vulnerable, "actions")])).code).toBe(1);
  });

  it("fixes files in place with --fix", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "gha-guard-"));
    cpSync(path.join(fixtures, "vulnerable"), dir, { recursive: true });
    const r = await cli(["--fix", "--format", "json", dir], dir);
    expect(r.stderr).toContain(
      "fixed GHA001 .github/workflows/triage.yml:13 github.event.issue.title -> $ISSUE_TITLE",
    );
    expect(readFileSync(path.join(dir, ".github/workflows/triage.yml"), "utf8")).toContain("ISSUE_TITLE:");
    const remaining = (JSON.parse(r.stdout) as { findings: { ruleId: string }[] }).findings.map(
      (f) => f.ruleId,
    );
    expect(remaining).not.toContain("GHA003");
  });

  it("handles usage errors", async () => {
    expect((await cli(["--format", "xml"])).code).toBe(2);
    expect((await cli(["--fail-on", "critical"])).code).toBe(2);
    expect((await cli(["--bogus"])).code).toBe(2);
    expect((await cli(["does-not-exist"])).code).toBe(2);
  });

  it("prints help, version and rules", async () => {
    expect((await cli(["--help"])).stdout).toContain("usage: gha-guard");
    expect((await cli(["--version"])).stdout).toMatch(/^gha-guard /);
    expect((await cli(["--list-rules"])).stdout).toContain("GHA009");
  });

  it("formats sarif", async () => {
    const r = await cli(["--format", "sarif", path.join(fixtures, "vulnerable")]);
    expect((JSON.parse(r.stdout) as { version: string }).version).toBe("2.1.0");
  });
});

describe("discovery", () => {
  it("skips fixture directories when scanning a repository root", async () => {
    const root = fileURLToPath(new URL("../", import.meta.url));
    const r = await cli(["--format", "json", "--fail-on", "none", root], root);
    const files = (JSON.parse(r.stdout) as { findings: { file: string }[] }).findings.map((f) => f.file);
    expect(files.some((f) => f.includes("fixtures"))).toBe(false);
  });
});

describe("isEntryPoint", () => {
  it("resolves symlinks such as node_modules/.bin/gha-guard", async () => {
    const { isEntryPoint } = await import("../src/cli.js");
    const { symlinkSync } = await import("node:fs");
    const dir = mkdtempSync(path.join(tmpdir(), "gha-guard-bin-"));
    const target = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
    const link = path.join(dir, "gha-guard");
    symlinkSync(target, link);
    const url = new URL("../src/cli.ts", import.meta.url).href;
    expect(isEntryPoint(link, url)).toBe(true);
    expect(isEntryPoint(target, url)).toBe(true);
    expect(isEntryPoint(path.join(dir, "other"), url)).toBe(false);
    expect(isEntryPoint(undefined, url)).toBe(false);
  });
});
