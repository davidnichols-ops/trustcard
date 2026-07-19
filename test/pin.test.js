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

test("pin file has the schema marker", () => {
  const { dir, path } = tmpPinPath();
  try {
    const a = new PinStore(path);
    a.pinServer("s@1", OBS);
    const raw = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(raw.schema, PINFILE_SCHEMA);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
