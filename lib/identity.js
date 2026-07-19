// Identity: what *is* a tool, cryptographically?
//
// A tool definition has three layers:
//   - semantic projection  — the fields that change what an agent can do or
//                            what it believes a tool does (name, description,
//                            input/output schemas, behavioral annotations).
//   - volatile surface     — presentation-only fields (title, icons, tags,
//                            arbitrary _meta) that never affect behavior.
//   - provenance           — who signed this exact definition (see provenance.js).
//
// toolDigest  = sha256(JCS(semantic projection))   — content-address of one tool
// toolsetDigest = sha256(JCS(sorted toolDigests))  — order-independent set digest
// serverDigest  = sha256(JCS(identity binding))    — pins serverInfo + protocol +
//                                                    toolsetDigest together
import { hashJson } from "./hash.js";
import { jsonEqual } from "./canon.js";

export const TRUSTCARD_META_KEY = "io.github.davidnichols-ops/trustcard";
export const MANIFEST_SCHEMA_VERSION = "trustcard.dev/manifest@1";
export const DEFAULT_PROTOCOL_VERSIONS = ["2025-06-18", "2024-11-05", "2024-10-07"];

// Fields that make up the semantic projection of a tool. Anything not listed
// here is volatile: changing it produces a SYNTACTIC-only diff.
const ANNOTATION_KEYS = ["title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"];

export function toolProjection(tool) {
  if (!tool || typeof tool !== "object") throw new TypeError("tool must be an object");
  const proj = { name: tool.name };
  if (tool.description !== undefined) proj.description = tool.description;
  if (tool.inputSchema !== undefined) proj.inputSchema = tool.inputSchema;
  if (tool.outputSchema !== undefined) proj.outputSchema = tool.outputSchema;
  if (tool.annotations && typeof tool.annotations === "object") {
    const ann = {};
    for (const k of ANNOTATION_KEYS) {
      if (tool.annotations[k] !== undefined) ann[k] = tool.annotations[k];
    }
    if (Object.keys(ann).length > 0) proj.annotations = ann;
  }
  // execution (e.g. taskSupport) changes how calls are dispatched — semantic.
  if (tool.execution !== undefined) proj.execution = tool.execution;
  return proj;
}

// Volatile fields = everything present on the tool but excluded from the
// projection. Used by the differ to label SYNTACTIC changes precisely.
export function volatileFields(tool) {
  const semantic = new Set(Object.keys(toolProjection(tool)));
  return Object.keys(tool ?? {}).filter((k) => !semantic.has(k));
}

export function toolDigest(tool) {
  return hashJson(toolProjection(tool));
}

export function toolsetDigest(tools) {
  const digests = (tools ?? []).map((t) => toolDigest(t));
  digests.sort();
  return hashJson({ toolset: digests });
}

// Bind the server-level identity: who answered (serverInfo), which protocol
// was negotiated, and the exact toolset that was enumerated.
export function serverDigest({ serverInfo, protocolVersion, tools }) {
  return hashJson({
    server: {
      name: serverInfo?.name ?? null,
      version: serverInfo?.version ?? null,
      title: serverInfo?.title ?? null,
    },
    protocolVersion: protocolVersion ?? null,
    toolset: toolsetDigest(tools),
  });
}

// The binding a trustcard-aware server attaches to its initialize result so a
// client can verify at handshake time — closing most of the TOCTOU window
// between discovery and execution.
export function handshakeBinding({ manifest }) {
  return {
    toolsetDigest: manifest.toolsetDigest,
    serverDigest: manifest.serverDigest,
    manifestDigest: manifest.manifestDigest,
    schema: MANIFEST_SCHEMA_VERSION,
  };
}

export function sameTool(a, b) {
  return jsonEqual(toolProjection(a), toolProjection(b));
}
