// The pin store: TOFU (trust-on-first-use) continuity for servers and publishers.
//
// Two kinds of pins live here:
//   server pins    — serverKey → { toolsetDigest, serverDigest, toolDigests, tools }
//   publisher pins — keyId    → { publicKey, firstSeen, source }
//
// TOFU is the right default for a decentralized ecosystem: the first time you
// connect you pin what you saw; every subsequent connection must match or
// produce an auditable, classified diff. The pinning file is the client's
// ground truth — it is what turns "the server said so" into "the server said
// the same thing it said last time".
import { readFileSync, writeFileSync, mkdirSync, renameSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export const PINFILE_SCHEMA = "trustcard.dev/pins@1";

export function defaultPinPath() {
  return process.env.TRUSTCARD_PINS ?? join(homedir(), ".config", "trustcard", "pins.json");
}

export class PinStore {
  constructor(path = defaultPinPath()) {
    this.path = path;
    this.data = { schema: PINFILE_SCHEMA, servers: {}, publishers: {} };
    this._load();
  }

  _load() {
    try {
      if (existsSync(this.path)) {
        const parsed = JSON.parse(readFileSync(this.path, "utf8"));
        if (parsed?.schema === PINFILE_SCHEMA) this.data = parsed;
      }
    } catch {
      // A corrupt pin file must never silently become "no pins": keep the
      // corrupt file for forensics and start empty-but-loud.
      this.corrupt = true;
    }
  }

  save() {
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = this.path + ".tmp";
    writeFileSync(tmp, JSON.stringify(this.data, null, 2) + "\n");
    renameSync(tmp, this.path); // atomic replace — a crashed write never halves the pin file
  }

  // --- server pins ---
  serverKey(serverId) {
    return typeof serverId === "string" ? serverId : `${serverId?.name ?? "?"}@${serverId?.version ?? "?"}`;
  }

  getServerPin(serverId) {
    return this.data.servers[this.serverKey(serverId)] ?? null;
  }

  pinServer(serverId, observation, publisherKeyId = null) {
    const key = this.serverKey(serverId);
    const existing = this.data.servers[key];
    this.data.servers[key] = {
      toolsetDigest: observation.toolsetDigest,
      serverDigest: observation.serverDigest,
      toolDigests: observation.toolDigests ?? {},
      tools: observation.tools,
      protocolVersion: observation.protocolVersion,
      publisherKeyId,
      firstPinnedAt: existing?.firstPinnedAt ?? new Date().toISOString(),
      lastPinnedAt: new Date().toISOString(),
      repinCount: (existing?.repinCount ?? 0) + (existing ? 1 : 0),
    };
    this.save();
    return this.data.servers[key];
  }

  removeServerPin(serverId) {
    delete this.data.servers[this.serverKey(serverId)];
    this.save();
  }

  // --- publisher pins (TOFU on Ed25519 keys) ---
  getPublisherPin(keyId) {
    return this.data.publishers[keyId] ?? null;
  }

  // Returns { status: "pinned" | "tofu-new" | "drift", pin }
  pinPublisherTofu(keyId, publicKey, source = "manifest") {
    const existing = this.data.publishers[keyId];
    if (existing) {
      if (existing.publicKey !== publicKey) {
        // Same keyId, different bytes should be impossible (keyId = hash of
        // bytes) — if it happens, treat as an attack signal, never overwrite.
        return { status: "drift", pin: existing };
      }
      return { status: "pinned", pin: existing };
    }
    const pin = { publicKey, firstSeen: new Date().toISOString(), source };
    this.data.publishers[keyId] = pin;
    this.save();
    return { status: "tofu-new", pin };
  }

  list() {
    return this.data;
  }
}
