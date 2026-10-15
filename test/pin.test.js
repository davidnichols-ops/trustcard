// Pin store: TOFU continuity, atomic persistence, corrupt-file safety.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PinStore, PINFILE_SCHEMA } from "../lib/pin.js";
import { toolsetDigest, serverDigest } from "../lib/identity.js";
import { TOOL_SEARCH, TOOL_FETCH } from "./helpers.js";

function tmpPinPath() {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-pins-"));
  return { dir, path: join(dir, "pins.json") };
}

const OBS = {
  tools: [TOOL_SEARCH],
  toolsetDigest: toolsetDigest([TOOL_SEARCH]),
  serverDigest: serverDigest({ serverInfo: { name: "s", version: "1" }, protocolVersion: "2025-06-18", tools: [TOOL_SEARCH] }),
  toolDigests: { search: "sha256:x" },
  protocolVersion: "2025-06-18",
};

test("pinServer persists and reloads (TOFU continuity across restarts)", () => {
  const { dir, path } = tmpPinPath();
  try {
    const a = new PinStore(path);
    a.pinServer("s@1", OBS);
    const b = new PinStore(path); // simulate process restart
    const pin = b.getServerPin("s@1");
    assert.equal(pin.toolsetDigest, OBS.toolsetDigest);
    assert.equal(pin.serverDigest, OBS.serverDigest);
    assert.ok(pin.firstPinnedAt);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("repin increments repinCount and keeps firstPinnedAt", () => {
  const { dir, path } = tmpPinPath();
  try {
    const a = new PinStore(path);
    a.pinServer("s@1", OBS);
    a.pinServer("s@1", OBS);
    const pin = a.getServerPin("s@1");
    assert.equal(pin.repinCount, 1);
    assert.ok(pin.firstPinnedAt <= pin.lastPinnedAt);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("publisher TOFU: first pin, then continuity, and drift is an attack signal", () => {
  const { dir, path } = tmpPinPath();
  try {
    const a = new PinStore(path);
    const r1 = a.pinPublisherTofu("sha256:k1", "PUBKEY_BYTES", "manifest");
    assert.equal(r1.status, "tofu-new");
    const r2 = a.pinPublisherTofu("sha256:k1", "PUBKEY_BYTES", "manifest");
    assert.equal(r2.status, "pinned");
    // same keyId, different bytes — must never overwrite, must flag
    const r3 = a.pinPublisherTofu("sha256:k1", "DIFFERENT_BYTES", "manifest");
    assert.equal(r3.status, "drift");
    assert.equal(a.getPublisherPin("sha256:k1").publicKey, "PUBKEY_BYTES");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("removeServerPin deletes the pin", () => {
  const { dir, path } = tmpPinPath();
  try {
    const a = new PinStore(path);
    a.pinServer("s@1", OBS);
    a.removeServerPin("s@1");
    assert.equal(a.getServerPin("s@1"), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("corrupt pin file does not crash and does not silently trust", () => {
  const { dir, path } = tmpPinPath();
  try {
    writeFileSync(path, "{ not valid json");
    const a = new PinStore(path);
    assert.ok(a.corrupt); // flagged, not silent
    assert.equal(a.getServerPin("anything"), null); // nothing trusted
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// --- Regression: pin identity binds origin, not just self-reported name@version
// Two servers that report no serverInfo used to collapse onto the key "?@?" —
// a pin for one would silently cover the other. With the caller-supplied
// origin in the key they stay distinct, and a named server's pin is bound to
// the route it was pinned through.

test("unnamed servers from different origins do not collide on ?@?", () => {
  const { dir, path } = tmpPinPath();
  try {
    const a = new PinStore(path);
    a.pinServer({ origin: "npx -y @evil/fake" }, OBS);
    a.pinServer({ origin: "npx -y @acme/real" }, OBS);
    const keys = Object.keys(a.list().servers);
    assert.equal(keys.length, 2);
    assert.ok(keys.every((k) => k.startsWith("?@?::")));
    assert.equal(a.getServerPin({ origin: "npx -y @evil/fake" }) !== null, true);
    assert.equal(a.getServerPin({ origin: "npx -y @acme/real" }) !== null, true);
    // and without origin context the legacy "?@?" collision shape remains isolated
    assert.equal(a.serverKey({}), "?@?");
    assert.equal(a.getServerPin({}), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("pin key binds self-reported identity to origin: name@version::origin", () => {
  const { dir, path } = tmpPinPath();
  try {
    const a = new PinStore(path);
    const key = a.serverKey({ name: "s", version: "1", origin: "npx -y @acme/s" });
    assert.equal(key, "s@1::npx -y @acme/s");
    a.pinServer({ name: "s", version: "1", origin: "npx -y @acme/s" }, OBS);
    const pin = a.getServerPin({ name: "s", version: "1", origin: "npx -y @acme/s" });
    assert.equal(pin.origin, "npx -y @acme/s");
    // a different origin claiming the same name@version is a different pin
    assert.equal(a.getServerPin({ name: "s", version: "1", origin: "npx -y @impostor/s" }), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("legacy name@version pins remain readable and migrate to origin-bound keys", () => {
  const { dir, path } = tmpPinPath();
  try {
    const a = new PinStore(path);
    a.pinServer("s@1", OBS); // legacy key, no origin context (pre-migration shape)
    // Reading with origin context falls back to the legacy pin (continuity)
    const read = a.getServerPin({ name: "s", version: "1", origin: "npx -y @acme/s" });
    assert.ok(read);
    assert.equal(read.toolsetDigest, OBS.toolsetDigest);
    // Re-pinning under origin context migrates the record, preserving history
    a.pinServer({ name: "s", version: "1", origin: "npx -y @acme/s" }, OBS);
    const data = a.list();
    assert.equal(data.servers["s@1"], undefined);
    const migrated = data.servers["s@1::npx -y @acme/s"];
    assert.ok(migrated);
    assert.equal(migrated.repinCount, 1);
    assert.equal(migrated.origin, "npx -y @acme/s");
    // migration survives reload
    const b = new PinStore(path);
    assert.ok(b.getServerPin({ name: "s", version: "1", origin: "npx -y @acme/s" }));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("unpin clears both origin-bound and legacy keys", () => {
  const { dir, path } = tmpPinPath();
  try {
    const a = new PinStore(path);
    a.pinServer("s@1", OBS);
    a.pinServer({ name: "s", version: "1", origin: "o" }, OBS);
    a.removeServerPin("s@1::o");
    assert.equal(a.list().servers["s@1::o"], undefined);
    a.removeServerPin("s@1");
    assert.equal(a.list().servers["s@1"], undefined);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("pin file has the schema marker", () => {
  const { dir, path } = tmpPinPath();
  try {
    const a = new PinStore(path);
    a.pinServer("s@1", OBS);
    const raw = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(raw.schema, PINFILE_SCHEMA);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
