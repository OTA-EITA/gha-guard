import type { Finding, Rule } from "../types.js";
import { severityRank } from "../types.js";
import type { Workflow } from "../workflow.js";
import { checkHygiene } from "./hygiene.js";
import { checkInjection } from "./injection.js";
import { checkPermissions } from "./permissions.js";
import { checkPinning } from "./pinning.js";
import { checkPwnRequest } from "./pwn-request.js";

export const rules: Rule[] = [
  {
    id: "GHA000",
    severity: "low",
    title: "Unparsable file",
    description: "The file is not valid YAML, so it was skipped; the other files are still checked.",
  },
  {
    id: "GHA001",
    severity: "high",
    title: "Script injection",
    description: "Untrusted input such as an issue title is interpolated into run: or github-script.",
  },
  {
    id: "GHA002",
    severity: "high",
    title: "Pwn request",
    description: "pull_request_target or workflow_run checks out and runs pull request code with secrets.",
  },
  {
    id: "GHA003",
    severity: "medium",
    title: "Missing permissions",
    description: "No permissions block, so jobs get the repository's default token permissions.",
  },
  {
    id: "GHA004",
    severity: "high",
    title: "write-all permissions",
    description: "The token can write to everything the repository allows.",
  },
  {
    id: "GHA005",
    severity: "medium",
    title: "Unpinned action",
    description: "Actions or images referenced by a mutable tag instead of a commit SHA or digest.",
  },
  {
    id: "GHA006",
    severity: "low",
    title: "Persisted checkout credentials",
    description: "actions/checkout leaves the token in .git/config for later steps.",
  },
  {
    id: "GHA007",
    severity: "high",
    title: "Insecure commands",
    description: "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables deprecated, injectable workflow commands.",
  },
  {
    id: "GHA008",
    severity: "medium",
    title: "Self-hosted runner on pull requests",
    description: "Untrusted pull request code runs on a persistent self-hosted runner.",
  },
  {
    id: "GHA009",
    severity: "low",
    title: "secrets: inherit",
    description: "Every secret is passed to a reusable workflow.",
  },
];

const checks = [checkInjection, checkPwnRequest, checkPermissions, checkPinning, checkHygiene];

/** Runs every rule and sorts findings by severity, then position. */
export function analyze(wf: Workflow): Finding[] {
  return checks
    .flatMap((check) => check(wf))
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || a.line - b.line);
}
