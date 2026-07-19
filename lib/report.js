// Rendering: trust cards and diff reports for humans.
export function badge(status, c) {
  const map = {
    PASS: c("32", "PASS"),
    WARN: c("33", "WARN"),
    FAIL: c("31", "FAIL"),
    CONFIG_REQUIRED: c("34", "CONFIG"),
    REQUIRED: c("34", "REQUIRED"),
    PINNED: c("32", "PINNED"),
    OBSERVED: c("36", "OBSERVED"),
    MISMATCH: c("31", "MISMATCH"),
    SUSPECT: c("33", "SUSPECT"),
    REVOKED: c("31;1", "REVOKED"),
    BREAKING: c("31;1", "BREAKING"),
    PERMISSION_CHANGE: c("35", "PERM-CHG"),
    ANNOTATION_DOWNGRADE: c("35;1", "POISON?"),
    NON_BREAKING: c("33", "NON-BRK"),
    SYNTACTIC: c("36", "SYNTACTIC"),
    NONE: c("32", "IDENTICAL"),
  };
  return map[status] ?? c("2", status ?? "UNKNOWN");
}

const short = (d) => (d ? d.replace("sha256:", "").slice(0, 12) : "—");

export function printFingerprint(card, c) {
  const bold = (s) => c("1", s);
  const dim = (s) => c("2", s);
  const name = card.observation?.serverInfo?.name ?? card.spec.split("/").pop();
  console.log("");
  console.log(`${bold("Trustcard")}: ${bold(name)}  ${dim(card.spec)}`);
  console.log(dim("─".repeat(72)));
  const o = card.observation;
  if (o?.error) {
    console.log(`${"Probe".padEnd(22)} ${c("31", "FAIL")}  ${dim(o.error)}`);
  } else if (o) {
    console.log(`${"Server".padEnd(22)} ${o.serverInfo?.name ?? "?"}@${o.serverInfo?.version ?? "?"} · protocol ${o.protocolVersion ?? "?"}`);
    console.log(`${"Tools".padEnd(22)} ${o.tools.length} enumerated`);
    console.log(`${"Toolset digest".padEnd(22)} ${c("36", short(o.toolsetDigest))}  ${dim(o.toolsetDigest)}`);
    console.log(`${"Server digest".padEnd(22)} ${c("36", short(o.serverDigest))}  ${dim(o.serverDigest)}`);
    if (o.handshakeBinding) {
      console.log(`${"Handshake binding".padEnd(22)} ${c("36", "present")} ${dim("(server is trustcard-aware)")}`);
    }
  }
  if (card.package?.ok) {
    console.log(`${"Package".padEnd(22)} ${card.package.name}@${card.package.version}`);
    console.log(`${"Artifact integrity".padEnd(22)} ${dim(card.package.integrity ?? "—")}`);
  }
  if (card.provenance) {
    const p = card.provenance;
    console.log(`${"Manifest".padEnd(22)} ${p.ok ? c("32", "VERIFIED") : c("31", "INVALID")} ${p.keyId ? dim(`key ${short(p.keyId)}`) : ""} ${p.publisherTrust ? dim(`(${p.publisherTrust})`) : ""}`);
    for (const e of p.errors ?? []) console.log(`${"".padEnd(22)} ${c("31", "✗")} ${dim(e)}`);
    if (card.binding) {
      console.log(`${"Declared↔observed".padEnd(22)} ${card.binding.consistent ? c("32", "CONSISTENT") : c("31", "DRIFT")}`);
      for (const pr of card.binding.problems ?? []) console.log(`${"".padEnd(22)} ${c("31", "✗")} ${dim(pr)}`);
    }
  } else {
    console.log(`${"Manifest".padEnd(22)} ${dim("none provided — provenance unverified")}`);
  }
  if (card.pin) {
    if (card.pin.status === "unpinned") {
      console.log(`${"Pin".padEnd(22)} ${c("33", "UNPINNED")} ${dim("first observation — run `trustcard pin` to trust-on-first-use")}`);
    } else if (card.drift?.status === "match") {
      console.log(`${"Pin".padEnd(22)} ${c("32", "MATCH")} ${dim("identical to your pin since " + (card.pin.firstPinnedAt ?? "?"))}`);
    } else if (card.drift) {
      console.log(`${"Pin".padEnd(22)} ${c("31", "DRIFT")} ${dim(card.drift.summary)}`);
    }
  }
  console.log(dim("─".repeat(72)));
  console.log("");
}

export function printDiff(diff, c, { verbose = false } = {}) {
  const bold = (s) => c("1", s);
  const dim = (s) => c("2", s);
  console.log("");
  console.log(`${bold("Toolset diff")}: ${badge(diff.overall, c)}  ${dim(diff.summary)}`);
  console.log(dim("─".repeat(72)));
  for (const d of diff.toolDiffs) {
    if (d.level === "NONE" && !verbose) continue;
    console.log(`${badge(d.level, c)}  ${bold(d.tool)}`);
    for (const f of d.findings ?? []) {
      console.log(`    ${c("2", "·")} ${f.kind}: ${dim(f.detail)}`);
    }
  }
  console.log(dim("─".repeat(72)));
  console.log("");
}
