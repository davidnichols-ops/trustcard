// Fingerprint: the full identity card for one server, combining
//   - package identity   (npm dist.integrity — content hash of the tarball)
//   - observed identity  (serverDigest/toolsetDigest from a live probe)
//   - provenance         (signed manifest, if one exists)
//   - trust state        (pin continuity from the client's pin store)
import { exec as execCb } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync, existsSync } from "node:fs";
import { observeServer } from "./observe.js";
import { verifyManifest, bindingConsistency } from "./provenance.js";
import { diffToolsets } from "./diff.js";

const exec = promisify(execCb);

export async function packageIdentity(spec) {
  try {
    const { stdout } = await exec(
      `npm view ${JSON.stringify(spec)} name version dist.integrity dist.tarball --json`,
      { timeout: 30_000, env: process.env }
    );
    const info = JSON.parse(stdout);
    return {
      ok: true,
      name: info.name,
      version: info.version,
      integrity: info.dist?.integrity ?? null, // e.g. sha512-... — content hash of the tarball
      tarball: info.dist?.tarball ?? null,
    };
  } catch (e) {
    return { ok: false, error: (e.message ?? "").slice(0, 160) };
  }
}

export async function fingerprint(spec, { env = {}, manifestPath = null, pinStore = null, protocolVersions } = {}) {
  const card = {
    spec,
    at: new Date().toISOString(),
    package: await packageIdentity(spec),
    observation: null,
    manifest: null,
    provenance: null,
    binding: null,
    pin: null,
    drift: null,
  };

  card.observation = await observeServer({ cmd: "npx", args: ["-y", spec], env, protocolVersions });

  // Load + verify a signed manifest if provided (file path or URL).
  let manifest = null;
  if (manifestPath) {
    try {
      const raw = manifestPath.startsWith("http")
        ? await (await fetch(manifestPath)).text()
        : readFileSync(manifestPath, "utf8");
      manifest = JSON.parse(raw);
    } catch (e) {
      card.provenance = { ok: false, errors: [`could not load manifest: ${e.message}`] };
    }
  }
  if (manifest) {
    card.manifest = { manifestDigest: manifest.manifestDigest, keyId: manifest.publisher?.keyId, issuedAt: manifest.issuedAt };
    card.provenance = verifyManifest(manifest);
    if (card.provenance.ok && pinStore) {
      const tofu = pinStore.pinPublisherTofu(card.provenance.keyId, manifest.publisher.publicKey, manifestPath);
      card.provenance.publisherTrust = tofu.status; // "tofu-new" | "pinned" | "drift"
    }
    if (card.provenance.ok && !card.observation.error) {
      card.binding = bindingConsistency(manifest, card.observation);
    }
  }

  // Continuity against the client's own pin store.
  if (pinStore && !card.observation.error) {
    const key = pinStore.serverKey(card.observation.serverInfo ?? spec);
    const pin = pinStore.getServerPin(key);
    card.pin = pin ? { serverDigest: pin.serverDigest, toolsetDigest: pin.toolsetDigest, firstPinnedAt: pin.firstPinnedAt } : { status: "unpinned" };
    if (pin) {
      if (pin.toolsetDigest === card.observation.toolsetDigest) {
        card.drift = { status: "match", summary: "tool definitions identical to pin" };
      } else {
        const diff = diffToolsets(pin.tools ?? [], card.observation.tools);
        card.drift = { status: "drifted", ...diff };
      }
    }
  }

  return card;
}
