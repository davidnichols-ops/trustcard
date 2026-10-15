// Single source of truth for the package version — derived from package.json
// at load time so handshake clientInfo strings and reports can never drift
// from the shipped version.
import { readFileSync } from "node:fs";

export const TRUSTCARD_VERSION = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
).version;
