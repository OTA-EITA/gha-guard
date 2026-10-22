// Bundles the CLI and the GitHub Action entry point into single files.
// The Action bundle is committed (dist/action.js), as JavaScript actions run
// straight from the repository without installing dependencies.
import { readFileSync } from "node:fs";
import { build } from "esbuild";

const { version } = JSON.parse(readFileSync("package.json", "utf8"));

// yaml ships CommonJS for Node; give the ESM bundle a require() to load it with.
const requireShim =
  'import { createRequire as __createRequire } from "node:module"; const require = __createRequire(import.meta.url);';

const common = {
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  legalComments: "none",
  define: { __VERSION__: JSON.stringify(version) },
};

await build({
  ...common,
  entryPoints: ["src/cli.ts"],
  outfile: "dist/cli.js",
  banner: { js: `#!/usr/bin/env node\n${requireShim}` },
});
await build({
  ...common,
  entryPoints: ["src/action.ts"],
  outfile: "dist/action.js",
  banner: { js: requireShim },
});
