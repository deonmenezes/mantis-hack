#!/usr/bin/env node
// Thin launcher: resolves the prebuilt mantis binary from the
// per-platform package installed via optionalDependencies, runs a
// one-shot `mantis init` on first invocation (wires the Claude
// plugin into ~/.claude/plugins/mantis/ AND registers `mantis-mcp`
// as a user-scope MCP server with the `claude` CLI), then execs the
// requested binary with the operator's argv.
//
// No postinstall script (works in Bun and pnpm strict mode).
// The first-run init is gated on a marker file under ~/.Mantis/ so
// subsequent invocations skip straight to the exec — zero per-call
// overhead after the first.
"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const BIN_NAME = path.basename(process.argv[1] || "mantis");

const PLATFORM_MAP = {
  "darwin-arm64": "@deonmenezes/mantis-cli-darwin-arm64",
  "darwin-x64": "@deonmenezes/mantis-cli-darwin-x64",
  "linux-x64": "@deonmenezes/mantis-cli-linux-x64",
  "linux-arm64": "@deonmenezes/mantis-cli-linux-arm64",
};

const key = `${process.platform}-${process.arch}`;
const pkg = PLATFORM_MAP[key];

if (!pkg) {
  console.error(
    `[mantishack] no prebuilt binary for ${key}.\n` +
      `[mantishack] supported: ${Object.keys(PLATFORM_MAP).join(", ")}\n` +
      `[mantishack] build from source: https://github.com/deonmenezes/mantishack`
  );
  process.exit(1);
}

let binaryPath;
try {
  binaryPath = require.resolve(`${pkg}/bin/${BIN_NAME}`);
} catch (err) {
  console.error(
    `[mantishack] ${pkg} is not installed.\n` +
      `[mantishack] this usually means your package manager skipped optional dependencies.\n` +
      `[mantishack] try: npm i ${pkg} (or bun add ${pkg})`
  );
  console.error(err && err.message ? err.message : err);
  process.exit(1);
}

const mantisBinaryPath = require.resolve(`${pkg}/bin/mantis`);
const childEnv = {
  ...process.env,
  PATH: `${path.dirname(binaryPath)}${path.delimiter}${process.env.PATH || ""}`,
};

// --- First-run init: install Claude plugin + register MCP server ----
// The bundled plugin lives at <main-package-root>/plugin/claude-code.
// We pass it as MANTIS_PLUGIN_SRC so `mantis init` knows where to
// copy from without relying on the on-PATH binary's own search paths.
// Gated on ~/.Mantis/.npm-init-done so this runs exactly once per
// install (re-installs / version bumps update the file's contents,
// re-triggering init by version).
const stateDir = path.join(os.homedir(), ".Mantis");
const markerPath = path.join(stateDir, ".npm-init-done");
const pluginRoot = path.join(__dirname, "..", "plugin");

function readMarker() {
  try {
    return fs.readFileSync(markerPath, "utf8").trim();
  } catch {
    return "";
  }
}

function writeMarker(version) {
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(markerPath, `${version}\n`, { mode: 0o600 });
  } catch (e) {
    // Non-fatal — init still ran. We'll just re-run next time.
    console.error(`[mantishack] warn: could not write ${markerPath}: ${e.message}`);
  }
}

function packageVersion() {
  try {
    return require("../package.json").version || "unknown";
  } catch {
    return "unknown";
  }
}

function shouldRunInit() {
  // Skip when the operator is explicitly invoking `mantis init`
  // themselves — no point auto-running it before the user-requested
  // init.
  const argv = process.argv.slice(2);
  if (argv[0] === "init") return false;
  // Skip when this isn't the main `mantis` binary (the daemon and
  // mcp shims don't need plugin wiring).
  if (BIN_NAME !== "mantis") return false;
  // Skip when MANTIS_SKIP_AUTO_INIT=1.
  if (process.env.MANTIS_SKIP_AUTO_INIT === "1") return false;
  // Skip when the plugin directory wasn't bundled (e.g. an older
  // tarball, source builds).
  if (!fs.existsSync(path.join(pluginRoot, "claude-code"))) return false;
  // Skip when the marker matches the current package version.
  return readMarker() !== packageVersion();
}

// On macOS, npm-installed binaries inherit a `com.apple.quarantine`
// extended attribute. Gatekeeper then prompts the user (often via a
// password-style dialog) every single launch of an unsigned
// binary — and there are 3 of them (mantis, mantis-daemon,
// mantis-mcp), so the user sees the prompt three times. Strip the
// xattr on every invocation; it's cheap, idempotent, and harmless
// when the attr isn't there.
function stripQuarantineOnMacos() {
  if (process.platform !== "darwin") return;
  const binDir = path.dirname(binaryPath);
  for (const name of ["mantis", "mantis-daemon", "mantis-mcp"]) {
    const target = path.join(binDir, name);
    if (!fs.existsSync(target)) continue;
    // `xattr -d <attr> <file>` exits non-zero if the attr isn't
    // present — that's fine. stdio is ignored so the operator never
    // sees the "attribute not found" noise.
    spawnSync("xattr", ["-d", "com.apple.quarantine", target], { stdio: "ignore" });
  }
}

function runFirstRunInit() {
  process.stderr.write(
    "[mantishack] first run — wiring Claude plugin + MCP server (one-time setup)\n"
  );
  const initEnv = { ...childEnv, MANTIS_PLUGIN_SRC: pluginRoot };
  // We pass --no-daemon because the daemon's lifecycle is owned by
  // the user (or by `mantis hack` preflight); we just want plugin +
  // MCP wiring here.
  const initResult = spawnSync(
    mantisBinaryPath,
    ["init", "--no-daemon", "--plugin-src", pluginRoot],
    { stdio: "inherit", env: initEnv }
  );
  if (initResult.error || (initResult.status !== null && initResult.status !== 0)) {
    process.stderr.write(
      "[mantishack] warn: auto-init did not complete cleanly. Re-run later with `mantis init`.\n"
    );
    return;
  }
  writeMarker(packageVersion());
}

// Run the macOS quarantine strip before every spawn — cheap and
// idempotent. Without this, Gatekeeper prompts for the user
// password on each binary's first launch (so 3 prompts total
// across mantis / mantis-daemon / mantis-mcp).
stripQuarantineOnMacos();

if (shouldRunInit()) {
  runFirstRunInit();
}

// --- Main exec ------------------------------------------------------
const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env: childEnv,
});

if (result.error) {
  console.error(`[mantishack] failed to exec ${binaryPath}:`, result.error.message);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
