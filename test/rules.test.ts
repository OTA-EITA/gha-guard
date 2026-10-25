import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { analyze } from "../src/rules/index.js";
import { parseWorkflow } from "../src/workflow.js";

function check(path: string) {
  const wf = parseWorkflow(path, readFileSync(new URL(`./fixtures/${path}`, import.meta.url), "utf8"));
  if (!wf) throw new Error(`${path} is not a workflow`);
  return analyze(wf).map((f) => `${f.ruleId}@${String(f.line)}`);
}

describe("rules", () => {
  it("triage.yml: injection, pwn request, unpinned actions", () => {
    expect(check("vulnerable/.github/workflows/triage.yml")).toEqual([
      "GHA002@10",
      "GHA001@15",
      "GHA001@16",
      "GHA001@20",
      "GHA003@1",
      "GHA005@21", // third-party action: medium
      "GHA005@10", // first-party actions: low
      "GHA006@10",
      "GHA005@17",
    ]);
  });

  it("release.yml: write-all, insecure commands, self-hosted, secrets: inherit", () => {
    expect(check("vulnerable/.github/workflows/release.yml")).toEqual([
      "GHA004@1",
      "GHA007@1",
      "GHA005@13",
      "GHA009@14",
    ]);
  });

  it("lint.yml: self-hosted runner on pull requests and pwsh injection (low: pull_request only)", () => {
    expect(check("vulnerable/.github/workflows/lint.yml")).toEqual(["GHA003@1", "GHA008@4", "GHA001@8"]);
  });

  it("composite actions are checked for injection but not permissions", () => {
    expect(check("vulnerable/actions/notify/action.yml")).toEqual(["GHA001@6"]);
  });

  it("GHA001 points at the line and column of each expression, also inside block scalars", () => {
    const wf = parseWorkflow(
      "x.yml",
      [
        "on: issues",
        "permissions: {}",
        "jobs:",
        "  a:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: |",
        "          echo start",
        '          echo "${{ github.event.issue.title }}"',
        "      - run: >",
        "          echo",
        "          ${{ github.event.issue.body }}",
        "      - uses: actions/github-script@v7",
        "        with:",
        "          script: |",
        "            const a = 1",
        "            console.log('${{ github.event.issue.title }}')",
        "",
      ].join("\n"),
    );
    const found = wf ? analyze(wf).filter((f) => f.ruleId === "GHA001") : [];
    expect(found.map((f) => `${String(f.line)}:${String(f.column)}`)).toEqual(["9:17", "12:11", "17:26"]);
  });

  it("reports the same problem on the same line once", () => {
    const wf = parseWorkflow(
      "x.yml",
      [
        "on: issues",
        "permissions: {}",
        "jobs:",
        "  a:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: |",
        "          git checkout -B ${{ github.head_ref }} origin/${{ github.head_ref }}",
        "          git push origin HEAD:${{ github.head_ref }}",
        "",
      ].join("\n"),
    );
    const found = wf ? analyze(wf).filter((f) => f.ruleId === "GHA001") : [];
    expect(found.map((f) => `${String(f.line)}:${String(f.column)}`)).toEqual(["8:27", "9:32"]);
  });

  it("a hardened workflow has no findings", () => {
    expect(check("clean/.github/workflows/ci.yml")).toEqual([]);
  });

  it("non-workflow YAML is ignored and invalid YAML is an error", () => {
    expect(parseWorkflow("x.yml", "key: value\n")).toBeNull();
    expect(parseWorkflow("x.yml", "- a\n- b\n")).toBeNull();
    expect(() => parseWorkflow("bad.yml", "jobs: [\n")).toThrow(/bad.yml/);
  });

  it("job-level permissions and reusable workflows satisfy GHA003", () => {
    const wf = parseWorkflow(
      "x.yml",
      "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions: {contents: read}\n    steps: []\n  b:\n    uses: org/repo/.github/workflows/x.yml@0123456789012345678901234567890123456789\n",
    );
    expect(wf && analyze(wf).map((f) => f.ruleId)).toEqual([]);
  });

  it("job-level write-all and step-level insecure commands", () => {
    const wf = parseWorkflow(
      "x.yml",
      [
        "on: push",
        "permissions: {}",
        "jobs:",
        "  a:",
        "    runs-on: ubuntu-latest",
        "    permissions: write-all",
        "    steps:",
        "      - run: echo hi",
        "        env:",
        "          ACTIONS_ALLOW_UNSECURE_COMMANDS: true",
        "",
      ].join("\n"),
    );
    expect(wf && analyze(wf).map((f) => `${f.ruleId}@${String(f.line)}`)).toEqual(["GHA004@4", "GHA007@8"]);
  });
});
