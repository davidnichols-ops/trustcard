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
  //
  // Keying contract: a server self-reports name+version, which any impostor can
  // copy. When the caller knows the *origin* it connected through (the npm spec
  // or command line the operator configured), the key binds both:
  //   {name:"s",version:"1",origin:"npx -y @acme/s"} → "s@1::npx -y @acme/s"
  // A server with no usable self-report falls back to the origin alone instead
  // of "?@?", so two unnamed servers from different origins never collide.
  // Pins written before origin binding keep their bare "name@version" keys;
  // getServerPin reads them through the fallback and pinServer migrates them.
  serverKey(serverId) {
    if (typeof serverId === "string") return serverId;
    const name = serverId?.name ?? "?";
    const version = serverId?.version ?? "?";
    const origin = typeof serverId?.origin === "string" && serverId.origin.trim() ? serverId.origin.trim() : null;
    const base = `${name}@${version}`;
    return origin ? `${base}::${origin}` : base;
  }

  // The pre-origin-binding key for an origin-bound key ("s@1::src" → "s@1").
  static legacyKeyOf(key) {
    const i = typeof key === "string" ? key.indexOf("::") : -1;
    return i === -1 ? null : key.slice(0, i);
  }

  getServerPin(serverId) {
    const key = this.serverKey(serverId);
    const pin = this.data.servers[key];
    if (pin) return pin;
    // Legacy read path: pins written before origin binding were keyed by
    // self-reported name@version alone.
    const legacy = PinStore.legacyKeyOf(key);
    return legacy ? (this.data.servers[legacy] ?? null) : null;
  }

  pinServer(serverId, observation, publisherKeyId = null) {
    const key = this.serverKey(serverId);
    // Migrate a bare "name@version" pin to its origin-bound key, preserving
    // continuity metadata (firstPinnedAt/repinCount) instead of restarting TOFU.
    const legacy = PinStore.legacyKeyOf(key);
    if (legacy && !this.data.servers[key] && this.data.servers[legacy]) {
      this.data.servers[key] = this.data.servers[legacy];
      delete this.data.servers[legacy];
    }
    const existing = this.data.servers[key];
    const origin = typeof serverId === "object" && serverId?.origin?.trim() ? serverId.origin.trim() : null;
    this.data.servers[key] = {
      toolsetDigest: observation.toolsetDigest,
      serverDigest: observation.serverDigest,
      toolDigests: observation.toolDigests ?? {},
      tools: observation.tools,
      protocolVersion: observation.protocolVersion,
      publisherKeyId,
      origin: origin ?? existing?.origin ?? null,
      firstPinnedAt: existing?.firstPinnedAt ?? new Date().toISOString(),
      lastPinnedAt: new Date().toISOString(),
      repinCount: (existing?.repinCount ?? 0) + (existing ? 1 : 0),
    };
    this.save();
    return this.data.servers[key];
  }

  removeServerPin(serverId) {
    const key = this.serverKey(serverId);
    delete this.data.servers[key];
    // Allow `unpin <name@version>` to also clear a legacy (unbound) record.
    const legacy = PinStore.legacyKeyOf(key);
    if (legacy) delete this.data.servers[legacy];
    this.save();
  }

  // --- capability-descriptor pins (v2, additive) ------------------------------
  // Pin by descriptor content-address rather than by server name. This is the
  // smallest step that lets the new descriptor model be pinned WITHOUT the
  // assumption that "server == trusted object": the pinned thing is a signed
  // (interface, implementation, provenance) binding, keyed by its own digest.
  descriptorKey(descriptorDigest) {
    return descriptorDigest;
  }

  getDescriptorPin(descriptorDigest) {
    return (this.data.descriptors ?? {})[this.descriptorKey(descriptorDigest)] ?? null;
  }

  pinDescriptor(descriptor, publisherKeyId = null) {
    if (!this.data.descriptors) this.data.descriptors = {};
    const key = this.descriptorKey(descriptor.descriptorDigest);
    const existing = this.data.descriptors[key];
    this.data.descriptors[key] = {
      descriptorDigest: descriptor.descriptorDigest,
      interfaceDigest: descriptor.capability?.interfaceDigest ?? null,
      namespace: descriptor.capability?.namespace ?? null,
      implementation: descriptor.implementation ?? { kind: "unresolved" },
      publisherKeyId: publisherKeyId ?? descriptor.provenance?.keyId ?? null,
      firstPinnedAt: existing?.firstPinnedAt ?? new Date().toISOString(),
      lastPinnedAt: new Date().toISOString(),
    };
    this.save();
    return this.data.descriptors[key];
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
