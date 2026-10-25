import { privilegedEvents } from "../events.js";
import { exposures, withEnvironment, worst } from "../exposure.js";
import type { Rating } from "../exposure.js";
import type { Finding, Severity } from "../types.js";
import type { Step, Workflow } from "../workflow.js";

/**
 * AI coding agents in workflows normally refuse to run for people without
 * write access. Opening that up lets anyone who can open an issue, comment or
 * send a pull request steer the agent, and text they write can carry prompt
 * injection that makes the agent use whatever tools it was given.
 */

/** gh subcommands that only read. */
const readOnlyGh =
  /^gh\s+(?:(?:issue|pr|repo|run|release|label|workflow|gist)\s+(?:view|list|diff|status|checks)|search)\b/;

/** Splits "Bash(gh pr:*),Read Edit" into tools, keeping commas inside parentheses. */
function splitTools(list: string): string[] {
  const tools: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of list) {
    if (ch === "(") depth++;
    if (ch === ")") depth = Math.max(0, depth - 1);
    if (depth === 0 && (ch === "," || /\s/.test(ch))) {
      if (current) tools.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  if (current) tools.push(current);
  return tools;
}

/** Tools that can run commands or write through gh, beyond what the action always allows. */
function riskyTools(step: Step): string[] {
  const lists: string[] = [];
  const args = step.with.claude_args ?? "";
  for (const m of args.matchAll(/--allowed-?tools(?:=|\s+)(?:"([^"]*)"|'([^']*)'|(\S+))/gi)) {
    lists.push(m[1] ?? m[2] ?? m[3] ?? "");
  }
  // Inputs of v0.x, replaced by claude_args in v1.
  if (step.with.allowed_tools) lists.push(step.with.allowed_tools);
  return lists.flatMap(splitTools).filter((tool) => {
    const bash = /^Bash(?:\((.*)\))?$/i.exec(tool);
    if (!bash) return false;
    const command = (bash[1] ?? "*").replace(/:\*$/, "").trim();
    return !readOnlyGh.test(command);
  });
}

interface Agent {
  action: string;
  who: string;
  severity: Severity;
  detail: string;
}

function agentOf(step: Step): Agent | undefined {
  const action = step.uses?.split("@")[0];
  if (action === "anthropics/claude-code-action") {
    const users = step.with.allowed_non_write_users?.trim();
    if (!users) return undefined;
    const risky = riskyTools(step);
    return {
      action,
      who: `allowed_non_write_users: ${users === "*" ? '"*"' : users}`,
      severity: risky.length ? "high" : "medium",
      detail: risky.length ? `, including ${risky.join(", ")}` : "",
    };
  }
  if (action === "openai/codex-action") {
    const users = step.with["allow-users"]?.trim();
    if (!users) return undefined;
    const unsandboxed =
      step.with.sandbox === "danger-full-access" ||
      step.with["safety-strategy"] === "unsafe" ||
      /danger-full-access|dangerously-bypass/.test(step.with["codex-args"] ?? "");
    return {
      action,
      who: `allow-users: ${users === "*" ? '"*"' : users}`,
      severity: unsandboxed ? "high" : "medium",
      detail: unsandboxed ? ", without a sandbox" : "",
    };
  }
  return undefined;
}

export function checkAgents(wf: Workflow): Finding[] {
  const events = wf.triggers.filter((t) => privilegedEvents.has(t));
  if (events.length === 0) return [];
  const findings: Finding[] = [];
  for (const job of wf.jobs) {
    job.steps.forEach((step, index) => {
      const agent = agentOf(step);
      if (!agent) return;
      const ratings: Rating[] = exposures(wf, job, index, events).map(({ event, verdict }) => {
        const base = `${agent.action} lets people without write access drive the agent (${agent.who}) on ${event} events; prompt injection in what they write could make it use its tools${agent.detail}`;
        if (verdict.kind === "open") return { severity: agent.severity, note: base };
        if (verdict.strength === "actor") {
          return { severity: "low", note: `${base}, but it only runs when ${verdict.reason}` };
        }
        return { severity: "medium", note: `${base}; it runs when ${verdict.reason}` };
      });
      const found = worst(ratings);
      if (!found) return;
      const rating = withEnvironment(found, job);
      findings.push({
        ruleId: "GHA010",
        severity: rating.severity,
        file: wf.file,
        line: step.line,
        message: rating.note,
        help: "Drop the allow list, or limit the agent to read-only tools and keep the job's permissions and token minimal.",
      });
    });
  }
  return findings;
}
