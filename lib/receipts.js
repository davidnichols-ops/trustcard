// Receipts: reproducibility for tool calls.
//
// A receipt binds {exact contract version} × {exact arguments} → {result digest}.
// Two calls are *reproducible* when contract digest and arguments digest match;
// comparing resultDigests then tells you whether the server's behavior is
// deterministic under an identical contract — which is the only notion of
// reproducibility that means anything when tools are mutable.
import { readFileSync, appendFileSync, existsSync } from "node:fs";

export function makeReceiptSink(path) {
  return (receipt) => {
    appendFileSync(path, JSON.stringify(receipt) + "\n");
  };
}

export function loadReceipts(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

// Group receipts by (tool, toolsetDigest, argumentsDigest) and report which
// groups produced more than one distinct result — non-reproducible behavior
// under an identical contract.
export function reproducibilityReport(receipts) {
  const groups = new Map();
  for (const r of receipts) {
    const key = [r.tool, r.toolsetDigest, r.argumentsDigest].join("|");
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  const rows = [];
  for (const [key, rs] of groups) {
    const results = new Set(rs.map((r) => r.resultDigest));
    rows.push({
      tool: rs[0].tool,
      toolsetDigest: rs[0].toolsetDigest,
      argumentsDigest: rs[0].argumentsDigest,
      calls: rs.length,
      distinctResults: results.size,
      reproducible: results.size <= 1,
    });
  }
  return rows;
}
