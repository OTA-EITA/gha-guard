import { describe, expect, it } from "vitest";
import { jobVerdict, stepVerdict } from "../src/gates.js";
import type { Verdict } from "../src/gates.js";
import { parseWorkflow } from "../src/workflow.js";

/** A workflow with one job whose `if:` is `cond`. */
function jobIf(cond: string, on = "pull_request_target"): string {
  return `on: ${on}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    if: ${cond}\n    steps:\n      - run: echo hi\n`;
}

function load(source: string) {
  const wf = parseWorkflow("x.yml", source);
  if (!wf) throw new Error("not a workflow");
  return wf;
}

function job(source: string, event: string, id = "a"): Verdict {
  const wf = load(source);
  const j = wf.jobs.find((x) => x.id === id);
  if (!j) throw new Error(`no job ${id}`);
  return jobVerdict(wf, j, event);
}

function step(source: string, event: string, index: number, id = "a"): Verdict {
  const wf = load(source);
  const j = wf.jobs.find((x) => x.id === id);
  if (!j) throw new Error(`no job ${id}`);
  return stepVerdict(wf, j, index, event);
}

const kind = (v: Verdict) => (v.kind === "gated" ? `gated:${v.strength}` : v.kind);

describe("jobVerdict", () => {
  it("never runs with if: false or a mismatched event", () => {
    expect(kind(job(jobIf("false"), "pull_request_target"))).toBe("never");
    expect(kind(job(jobIf("${{ false }}"), "pull_request_target"))).toBe("never");
    expect(kind(job(jobIf("github.event_name == 'schedule'"), "pull_request_target"))).toBe("never");
    expect(kind(job(jobIf("github.event_name != 'pull_request_target'"), "pull_request_target"))).toBe(
      "never",
    );
  });

  it("is open without a condition, with an unknown one or with one it cannot parse", () => {
    const plain = "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n";
    expect(kind(job(plain, "issues"))).toBe("open");
    expect(kind(job(jobIf("github.repository == 'a/b'"), "pull_request_target"))).toBe("open");
    expect(kind(job(jobIf("github.event_name == 'pull_request_target'"), "pull_request_target"))).toBe(
      "open",
    );
    expect(kind(job(jobIf(JSON.stringify("${{ a }} == ${{ b }}")), "pull_request_target"))).toBe("open");
    expect(kind(job(jobIf("a =="), "pull_request_target"))).toBe("open");
    expect(kind(job(jobIf("true"), "pull_request_target"))).toBe("open");
  });

  it("recognises conditions that only trusted actors can satisfy", () => {
    const actor = [
      "github.event.pull_request.author_association == 'OWNER'",
      "github.event.comment.author_association == 'MEMBER' || github.event.comment.author_association == 'COLLABORATOR'",
      'contains(fromJSON(\'["OWNER", "MEMBER"]\'), github.event.comment.author_association)',
      "contains('OWNER,MEMBER,COLLABORATOR', github.event.comment.author_association)",
      "github.actor == 'dependabot[bot]'",
      "'renovate[bot]' == github.triggering_actor",
      "github.event.pull_request.user.login == 'dependabot[bot]' && github.repository == 'a/b'",
      "github.event.pull_request.user.login == github.repository_owner",
      'contains(fromJSON(\'["alice", "bob"]\'), github.actor)',
      "github.event.pull_request.head.repo.full_name == github.repository",
      "github.event.pull_request.head.repo.full_name == 'a/b'",
      "github.event.pull_request.head.repo.fork == false",
      "!github.event.pull_request.head.repo.fork",
      "github.event.pull_request.head.repo.fork != true",
    ];
    for (const cond of actor) {
      expect(kind(job(jobIf(JSON.stringify(cond)), "pull_request_target")), cond).toBe("gated:actor");
    }
    const v = job(jobIf("github.actor == 'dependabot[bot]'"), "pull_request_target");
    expect(v.kind === "gated" && v.reason).toBe("github.actor is dependabot[bot]");
  });

  it("does not trust values outsiders can have or negations of gates", () => {
    const open = [
      "github.event.pull_request.author_association == 'CONTRIBUTOR'",
      "github.event.pull_request.author_association != 'NONE'",
      'contains(fromJSON(\'["OWNER", "NONE"]\'), github.event.comment.author_association)',
      "!(github.event.pull_request.author_association == 'OWNER')",
      "github.event.pull_request.author_association == 'OWNER' || contains(github.event.comment.body, '/run')",
      "github.actor != 'dependabot[bot]'",
      "contains(github.actor, 'bot')",
      "github.event.pull_request.head.repo.fork == true",
    ];
    for (const cond of open) {
      expect(kind(job(jobIf(JSON.stringify(cond)), "pull_request_target")), cond).toBe("open");
    }
  });

  it("checks workflow_run.event and the event-specific branches of a condition", () => {
    const superset = JSON.stringify(
      "github.event_name != 'workflow_run' || github.event.workflow_run.head_repository.full_name == github.repository",
    );
    expect(kind(job(jobIf(superset, "[push, workflow_run]"), "workflow_run"))).toBe("gated:actor");
    expect(kind(job(jobIf(superset, "[push, workflow_run]"), "push"))).toBe("open");
    const push = JSON.stringify(
      "github.event.workflow_run.event == 'push' && github.event.workflow_run.conclusion == 'success'",
    );
    expect(kind(job(jobIf(push, "workflow_run"), "workflow_run"))).toBe("gated:actor");
    expect(
      kind(job(jobIf("github.event.workflow_run.event == 'pull_request'", "workflow_run"), "workflow_run")),
    ).toBe("open");
    const labelOrSchedule = JSON.stringify(
      "github.repository == 'k/m' && ((github.event_name == 'pull_request_target' && contains(github.event.pull_request.labels.*.name, 'ok')) || github.event_name == 'schedule')",
    );
    expect(kind(job(jobIf(labelOrSchedule, "[pull_request_target, schedule]"), "pull_request_target"))).toBe(
      "gated:label",
    );
    expect(kind(job(jobIf(labelOrSchedule, "[pull_request_target, schedule]"), "schedule"))).toBe("open");
  });

  it("distinguishes a label being added from a label being present", () => {
    expect(kind(job(jobIf("github.event.label.name == 'safe'"), "pull_request_target"))).toBe(
      "gated:maintainer",
    );
    expect(kind(job(jobIf("github.event.pull_request.merged == true"), "pull_request_target"))).toBe(
      "gated:maintainer",
    );
    expect(
      kind(job(jobIf("contains(github.event.pull_request.labels.*.name, 'safe')"), "pull_request_target")),
    ).toBe("gated:label");
    // The strongest gate of a conjunction wins; the weakest branch of a disjunction.
    const both = JSON.stringify(
      "contains(github.event.pull_request.labels.*.name, 'safe') && github.event.pull_request.author_association == 'MEMBER'",
    );
    expect(kind(job(jobIf(both), "pull_request_target"))).toBe("gated:actor");
    const either = JSON.stringify(
      "github.event.label.name == 'safe' || github.event.pull_request.author_association == 'MEMBER'",
    );
    expect(kind(job(jobIf(either), "pull_request_target"))).toBe("gated:maintainer");
  });

  it("inherits the gates of needed jobs unless the condition uses a status function", () => {
    const src = [
      "on: pull_request_target",
      "jobs:",
      "  gate:",
      "    runs-on: ubuntu-latest",
      "    if: github.actor == 'dependabot[bot]'",
      "    steps: []",
      "  off:",
      "    runs-on: ubuntu-latest",
      "    if: false",
      "    steps: []",
      "  b:",
      "    needs: gate",
      "    runs-on: ubuntu-latest",
      "    if: success()",
      "    steps: []",
      "  c:",
      "    needs: [gate]",
      "    runs-on: ubuntu-latest",
      "    if: always()",
      "    steps: []",
      "  d:",
      "    needs: [off]",
      "    runs-on: ubuntu-latest",
      "    steps: []",
      "  e:",
      "    needs: [b, missing]",
      "    runs-on: ubuntu-latest",
      "    steps: []",
      "",
    ].join("\n");
    expect(kind(job(src, "pull_request_target", "b"))).toBe("gated:actor");
    expect(kind(job(src, "pull_request_target", "c"))).toBe("open");
    expect(kind(job(src, "pull_request_target", "d"))).toBe("never");
    expect(kind(job(src, "pull_request_target", "e"))).toBe("gated:actor");
  });

  it("treats inputs as empty for events other than workflow_dispatch and workflow_call", () => {
    expect(
      kind(job(jobIf("inputs.deploy", "[pull_request_target, workflow_dispatch]"), "pull_request_target")),
    ).toBe("never");
    expect(kind(job(jobIf("github.event.inputs.deploy", "[issues, workflow_dispatch]"), "issues"))).toBe(
      "never",
    );
    expect(
      kind(job(jobIf("inputs.deploy", "[pull_request_target, workflow_dispatch]"), "workflow_dispatch")),
    ).toBe("open");
    expect(kind(job(jobIf("inputs.deploy", "workflow_call"), "*"))).toBe("open");
  });

  it("does not loop on cyclic needs", () => {
    const src =
      "on: issues\njobs:\n  a:\n    needs: b\n    runs-on: x\n    steps: []\n  b:\n    needs: a\n    runs-on: x\n    steps: []\n";
    expect(kind(job(src, "issues"))).toBe("open");
  });
});

describe("stepVerdict", () => {
  const steps = (body: string[], on = "issue_comment") =>
    [`on: ${on}`, "jobs:", "  a:", "    runs-on: ubuntu-latest", "    steps:", ...body, ""].join("\n");

  it("combines the job and step conditions", () => {
    const src = steps([
      "      - run: echo 1",
      "        if: false",
      "      - run: echo 2",
      "        if: github.event.comment.author_association == 'OWNER'",
      "      - run: echo 3",
    ]);
    expect(kind(step(src, "issue_comment", 0))).toBe("never");
    expect(kind(step(src, "issue_comment", 1))).toBe("gated:actor");
    expect(kind(step(src, "issue_comment", 2))).toBe("open");
  });

  it("treats a failing permission check before the step as a gate", () => {
    const src = steps([
      "      - run: echo before",
      "      - uses: TheModdingInquisition/actions-team-membership@v1",
      "        with:",
      "          team: core",
      "          exit: true",
      "      - run: npm ci",
    ]);
    expect(kind(step(src, "issue_comment", 0))).toBe("open");
    const v = step(src, "issue_comment", 2);
    expect(kind(v)).toBe("gated:actor");
    expect(v.kind === "gated" && v.reason).toContain("TheModdingInquisition/actions-team-membership");

    const script = steps([
      "      - uses: actions/github-script@v7",
      "        with:",
      "          script: |",
      "            const r = await github.rest.repos.getCollaboratorPermissionLevel({ ...context.repo, username: context.actor });",
      "            if (r.data.permission !== 'admin') core.setFailed('no');",
      "      - run: npm ci",
    ]);
    expect(kind(step(script, "issue_comment", 1))).toBe("gated:actor");

    const allowlist = steps([
      "      - name: Check user",
      "        run: |",
      '          if [[ "${{ github.actor }}" != "$ALLOWED" ]]; then exit 1; fi',
      "      - run: npm ci",
      "      - run: |",
      '          echo "${GITHUB_ACTOR}"',
      "      - run: npm test",
    ]);
    expect(kind(step(allowlist, "issue_comment", 1))).toBe("gated:actor");
    // Printing the actor is not a check.
    const printing = steps(['      - run: echo "${GITHUB_ACTOR}"', "      - run: npm ci"]);
    expect(kind(step(printing, "issue_comment", 1))).toBe("open");

    // A check that only sets an output does not stop the job by itself.
    const output = steps([
      "      - uses: actions-cool/check-user-permission@v2",
      "        id: perm",
      "        with:",
      "          require: write",
      "      - run: npm ci",
      "      - run: npm test",
      "        if: steps.perm.outputs.require-result == 'true'",
    ]);
    expect(kind(step(output, "issue_comment", 1))).toBe("open");
    expect(kind(step(output, "issue_comment", 2))).toBe("gated:actor");
  });

  it("follows permission checks through job outputs", () => {
    const src = [
      "on: issue_comment",
      "jobs:",
      "  check:",
      "    runs-on: ubuntu-latest",
      "    outputs:",
      "      ok: ${{ steps.perm.outputs.require-result }}",
      "    steps:",
      "      - uses: actions-cool/check-user-permission@v2",
      "        id: perm",
      "  a:",
      "    needs: check",
      "    if: needs.check.outputs.ok == 'true'",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: npm ci",
      "",
    ].join("\n");
    expect(kind(step(src, "issue_comment", 0))).toBe("gated:actor");
  });
});
