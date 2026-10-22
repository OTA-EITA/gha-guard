import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { fix } from "../src/fix.js";
import { analyze } from "../src/rules/index.js";
import { parseWorkflow } from "../src/workflow.js";

function load(path: string, source?: string) {
  const text = source ?? readFileSync(new URL(`./fixtures/${path}`, import.meta.url), "utf8");
  const wf = parseWorkflow(path, text);
  if (!wf) throw new Error("not a workflow");
  return wf;
}

describe("fix", () => {
  it("moves untrusted input to env and quotes the reference", () => {
    const result = fix(load("vulnerable/.github/workflows/triage.yml"));
    expect(result.source).not.toBeNull();
    const out = result.source ?? "";
    expect(out).toContain('echo "Thanks for opening: ${ISSUE_TITLE}"');
    expect(out).toContain('echo "${HEAD_REF}"');
    expect(out).toContain("ISSUE_TITLE: ${{ github.event.issue.title }}");
    expect(out).toContain("HEAD_REF: ${{ github.head_ref }}");
    // permissions is inserted right after "on".
    expect(out).toMatch(/pull_request_target:\npermissions:\n {2}contents: read\njobs:/);
    // github-script is reported but not rewritten.
    expect(out).toContain('console.log("${{ github.event.issue.body }}")');

    const after = analyze(load("triage.yml", out)).map((f) => f.ruleId);
    expect(after.filter((id) => id === "GHA001")).toHaveLength(1); // only github-script remains
    expect(after).not.toContain("GHA003");
  });

  it("uses $env: for PowerShell", () => {
    const out = fix(load("vulnerable/.github/workflows/lint.yml")).source ?? "";
    expect(out).toContain('run: Write-Host "$env:PULL_REQUEST_TITLE"');
    expect(out).toContain("PULL_REQUEST_TITLE: ${{ github.event.pull_request.title }}");
  });

  it("does not clobber an existing env variable with the same name", () => {
    const src = [
      "on: push",
      "permissions: {}",
      "jobs:",
      "  a:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - env:",
      "          HEAD_REF: fixed",
      '        run: echo "${{ github.head_ref }}" $HEAD_REF',
      "",
    ].join("\n");
    const out = fix(load("x.yml", src)).source ?? "";
    expect(out).toContain("HEAD_REF: fixed");
    expect(out).toContain("HEAD_REF_2: ${{ github.head_ref }}");
    expect(out).toContain('echo "${HEAD_REF_2}" $HEAD_REF');
  });

  it("is a no-op on a clean workflow and idempotent", () => {
    expect(fix(load("clean/.github/workflows/ci.yml")).source).toBeNull();
    const once = fix(load("vulnerable/actions/notify/action.yml")).source ?? "";
    expect(once).toContain('echo "${HEAD_COMMIT_MESSAGE}"');
    expect(fix(load("action.yml", once)).source).toBeNull();
  });

  it("respects defaults.run.shell", () => {
    const src =
      "on: push\npermissions: {}\ndefaults:\n  run:\n    shell: cmd\njobs:\n  a:\n    runs-on: windows-latest\n    steps:\n      - run: echo ${{ github.head_ref }}\n";
    expect(fix(load("x.yml", src)).source).toContain("run: echo %HEAD_REF%");
  });
});
