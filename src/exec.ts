import type { Step } from "./workflow.js";

/**
 * Heuristics for "this step runs code from the checked-out tree": package
 * managers and build tools read scripts, hooks and build files from the
 * repository, and so do local scripts and local actions. A checkout of
 * untrusted code that is only diffed or uploaded is far less dangerous.
 */

/** Where a command can start: the start of a line, after ; && || | ( $( or a keyword such as sudo. */
const commandStart = String.raw`(?:^|[;&|({\x60]|\$\()\s*(?:(?:sudo|time|exec|then|do|else|if|while|!|env(?:\s+\w+=\S*)*)\s+)*(?:(?:npx|pnpx|bunx)\s+(?:--?[\w-]+\s+)*)?`;

/** Each pattern captures the command it describes in group 1. */
const commands = [
  String.raw`((?:npm|pnpm|bun)\s+(?:install|i|ci|run|run-script|test|t|build|exec|x|start))\b`,
  String.raw`(yarn(?:\s+(?!global\b)[a-z][\w:-]*)?)(?=[\s;&|)]|$)`,
  String.raw`(?:python3?\s+-m\s+)?(pip3?\s+install(?:\s+--?[\w-]+(?:=\S+)?)*?\s+(?:-e|--editable|-r|--requirement|\.(?=[\s[]|$)))`,
  String.raw`((?:poetry|pdm|pipenv)\s+(?:install|sync|run|build))\b`,
  String.raw`(uv\s+(?:sync|run|build|pip\s+install\s+(?:-e|-r|\.)))`,
  String.raw`(tox|nox|hatch\s+(?:run|build|test))\b`,
  String.raw`(python3?\s+setup\.py)\b`,
  String.raw`(?:python3?\s+-m\s+)?(pytest)\b`,
  String.raw`(python3?\s+(?!-)[\w./-]+\.py)\b`,
  String.raw`(make|cmake|ninja|meson|bazel|bazelisk|just)(?=[\s;&|)]|$)`,
  String.raw`(go\s+(?:build|test|run|generate|install|vet))\b`,
  String.raw`(cargo\s+(?:build|test|run|check|clippy|bench|install\s+--path))\b`,
  String.raw`(\.\/(?:gradlew|mvnw)|gradle|mvn)\b`,
  String.raw`(bundle\s+(?:install|exec)|rake)\b`,
  String.raw`(composer\s+(?:install|update|run|run-script))\b`,
  String.raw`(docker\s+(?:buildx\s+)?build|docker\s+compose|docker-compose)\b`,
  String.raw`((?:vercel|netlify)\s+build)\b`,
  String.raw`(dotnet\s+(?:build|test|run|restore|publish|pack))\b`,
  String.raw`(swift\s+(?:build|test|run)|xcodebuild)\b`,
  String.raw`(mix\s+(?:deps\.get|compile|test)|deno\s+(?:task|run|test))\b`,
  String.raw`((?:playwright|cypress)\s+(?:test|run)|jest|vitest|eslint|webpack|vite|turbo|nx|lerna)\b`,
  String.raw`(pre-commit\s+run)\b`,
  String.raw`(node\s+(?!-)[\w./-]+)`,
  String.raw`((?:bash|sh|zsh|source)\s+(?:-(?!c\b)\w+\s+)*(?!-)[\w./-]+)`,
  String.raw`(\.{1,2}\/[\w./-]+)`,
].map((c) => new RegExp(commandStart + c, "gm"));

/** Installing a tool globally does not run the repository's code. */
const globalInstall = /(?:^|\s)(?:-g|--global|global)(?:\s|$)/;

/** The first command in a shell script that runs code from the working tree, if any. */
export function scriptRunsCode(script: string): string | undefined {
  let best: { at: number; text: string } | undefined;
  for (const re of commands) {
    re.lastIndex = 0;
    for (const m of script.matchAll(re)) {
      const text = m[1];
      if (text === undefined) continue;
      const lineEnd = script.indexOf("\n", m.index);
      const rest = script.slice(m.index, lineEnd < 0 ? undefined : lineEnd);
      if (globalInstall.test(rest)) continue;
      const at = m.index + m[0].length - text.length;
      if (!best || at < best.at) best = { at, text: text.replace(/\s+/g, " ") };
      break;
    }
  }
  return best?.text;
}

/** Actions that build or test the working tree. */
const builders =
  /^(docker\/build-push-action|cypress-io\/github-action|bahmutov\/npm-install|borales\/actions-yarn|goreleaser\/goreleaser-action|pre-commit\/action|gradle\/gradle-build-action|devcontainers\/ci)@/;

/** What in a step runs code from the working tree, if anything. */
export function stepRunsCode(step: Step): string | undefined {
  if (step.uses?.startsWith("./")) return step.uses;
  if (step.uses && builders.test(step.uses)) return step.uses.split("@")[0];
  if (step.uses?.startsWith("actions/github-script@")) {
    return /require\(\s*['"`]\.{1,2}\/[^'"`]+['"`]\s*\)/.exec(step.with.script ?? "")?.[0];
  }
  return step.run === undefined ? undefined : scriptRunsCode(step.run);
}
