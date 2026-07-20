// Danger detector — fusion of heuristic + semantic similarity.
//
// The heuristic engine matches destructive verbs, write verbs, and dangerous
// parameters (path, command, sql, url, etc.) using word-boundary regex.
//
// The semantic engine builds TF-IDF vectors over tool names + descriptions
// and compares them against a curated corpus of known-dangerous action
// patterns. Cosine similarity gives a 0-1 score that captures semantic
// similarity even when no exact verb match exists (e.g. "purge cache" vs
// "invalidate stored data").
//
// The fusion layer combines both scores: if either engine flags a tool as
// dangerous, it's flagged. The confidence is higher when both agree.
//
// Zero dependencies — pure JS. The TF-IDF engine is ~200 lines and runs
// in <1ms per tool.

// --- Heuristic engine -------------------------------------------------------

const DESTRUCTIVE_VERBS = [
  "delete", "remove", "drop", "kill", "destroy", "truncate",
  "overwrite", "purge", "wipe", "force", "reset", "uninstall", "disable",
  "checkout", "push", "merge", "revert", "rollback",
  "reboot", "shutdown", "eject", "detach", "evict",
  "clear", "clean", "flush", "abort",
];
const WRITE_VERBS = [
  "write", "create", "update", "insert", "upsert", "push", "post", "put",
  "execute", "exec", "run", "send", "submit", "apply", "set", "install",
  "deploy", "merge", "edit", "modify", "patch",
];

// Dangerous parameter patterns — parameters that accept arbitrary input
// which could be used destructively.
const DANGEROUS_PARAMS = [
  { name: "command", weight: 0.9, reason: "accepts shell commands" },
  { name: "cmd", weight: 0.9, reason: "accepts shell commands" },
  { name: "sql", weight: 0.95, reason: "accepts SQL queries" },
  { name: "query", weight: 0.4, reason: "accepts queries (may include shell expressions)" },
  { name: "path", weight: 0.7, reason: "accepts file paths" },
  { name: "file_path", weight: 0.7, reason: "accepts file paths" },
  { name: "filepath", weight: 0.7, reason: "accepts file paths" },
  { name: "url", weight: 0.6, reason: "accepts URLs" },
  { name: "uri", weight: 0.5, reason: "accepts URIs" },
  { name: "script", weight: 0.85, reason: "accepts scripts" },
  { name: "code", weight: 0.7, reason: "accepts code" },
  { name: "expression", weight: 0.7, reason: "accepts expressions" },
  { name: "webhook", weight: 0.8, reason: "accepts webhook URLs" },
  { name: "token", weight: 0.5, reason: "accepts tokens" },
  { name: "data", weight: 0.5, reason: "accepts raw data" },
  { name: "content", weight: 0.4, reason: "accepts raw content" },
  { name: "payload", weight: 0.6, reason: "accepts payloads" },
  { name: "body", weight: 0.4, reason: "accepts request body" },
  { name: "cron", weight: 0.85, reason: "accepts cron expressions (persistence)" },
  { name: "schedule", weight: 0.6, reason: "accepts scheduling input" },
  { name: "files", weight: 0.65, reason: "accepts file paths for bulk operations" },
  { name: "target", weight: 0.6, reason: "accepts target paths for operations" },
  { name: "include_secrets", weight: 0.8, reason: "can expose secrets" },
  { name: "include_env", weight: 0.7, reason: "can expose environment variables" },
  { name: "config", weight: 0.4, reason: "accepts config file paths" },
  { name: "verbose", weight: 0.3, reason: "verbose mode may expose sensitive data" },
  { name: "output", weight: 0.4, reason: "accepts output paths" },
  { name: "dest", weight: 0.5, reason: "accepts destination paths" },
  { name: "cache_path", weight: 0.5, reason: "accepts cache file paths" },
];

function verbRegex(verb) {
  return new RegExp(`(^|[^a-z])${verb}([^a-z]|$)`, "i");
}

const DESTRUCTIVE_REGEXES = DESTRUCTIVE_VERBS.map(verbRegex);
const WRITE_REGEXES = WRITE_VERBS.map(verbRegex);

// Context-dependent verbs: these are only destructive when paired with
// destructive nouns. Without a destructive noun context, they describe
// benign operations (e.g. "clear thoughts", "reset state", "flush buffer").
const CONTEXT_DEPENDENT_VERBS = new Set([
  "clear", "clean", "flush", "reset", "abort", "disable",
]);
// Destructive nouns: when a context-dependent verb appears alongside one of
// these nouns, it's genuinely destructive. Without them, it's benign.
const DESTRUCTIVE_NOUNS = /\b(file|data|database|table|cache|storage|disk|drive|partition|history|log|entry|record|process|service|key|credential|token|secret|config|setting|account|user|session|connection|volume|device|mount|queue|task|job|node|cluster|index|schema|collection|document|image|container|pod|deployment|namespace|claim|role|binding|policy|rule|permission|access|grant|revoke|directory|folder|repository|branch|commit|tag|release|artifact|package|module|dependency|environment|variable|output|result|backup|snapshot|checkpoint|state|context|memory|buffer|pipe|stream|channel|socket|port|listener|handler|callback|subscription|subscription)\b/i;

// Safe tool patterns: idempotent, non-destructive operations that should
// never be flagged as dangerous regardless of verb matches.
const SAFE_TOOL_PATTERNS = [
  /create_(dir|directory|folder|path)/i,
  /make_dir/i,
  /mkdir/i,
  /ensure_dir/i,
  /makedirs/i,
  /sequential_?thinking/i,
];

function heuristicScore(tool) {
  const name = tool.name || "";
  const desc = tool.description || "";
  const text = `${name} ${desc}`;
  const params = extractParams(tool);

  const reasons = [];
  let score = 0;
  let maxScore = 1.0;

  // Destructive verb matching
  const destructiveMatches = [];
  for (let i = 0; i < DESTRUCTIVE_VERBS.length; i++) {
    if (DESTRUCTIVE_REGEXES[i].test(text)) {
      destructiveMatches.push(DESTRUCTIVE_VERBS[i]);
    }
  }
  if (destructiveMatches.length > 0) {
    // Context-aware scoring: context-dependent verbs (clear, reset, etc.)
    // are only destructive when paired with destructive nouns. If the text
    // contains ONLY context-dependent verbs and no destructive nouns, reduce
    // the score significantly.
    const hasDestructiveNoun = DESTRUCTIVE_NOUNS.test(text);
    const allContextDependent = destructiveMatches.every(v => CONTEXT_DEPENDENT_VERBS.has(v));
    if (allContextDependent && !hasDestructiveNoun) {
      // Context-dependent verb without destructive noun — likely benign
      // (e.g. "clear thoughts", "reset state", "flush buffer")
      score += 0.1;
      reasons.push(`context-dependent verb(s) without destructive noun: ${destructiveMatches.join(", ")}`);
    } else {
      score += 0.5;
      reasons.push(`destructive verb(s): ${destructiveMatches.join(", ")}`);
    }
  }

  // Write verb matching
  const writeMatches = [];
  for (let i = 0; i < WRITE_VERBS.length; i++) {
    if (WRITE_REGEXES[i].test(text)) {
      writeMatches.push(WRITE_VERBS[i]);
    }
  }
  if (writeMatches.length > 0 && destructiveMatches.length === 0) {
    score += 0.2;
    reasons.push(`write/exec verb(s): ${writeMatches.slice(0, 3).join(", ")}`);
  }

  // Dangerous parameter analysis
  // Use word-boundary matching to avoid false positives (e.g. "action_description"
  // should NOT match "script" just because "description" contains "script" as a substring)
  const dangerousParams = [];
  for (const dp of DANGEROUS_PARAMS) {
    for (const p of params) {
      const pl = p.toLowerCase();
      const dpl = dp.name.toLowerCase();
      if (pl === dpl || pl.startsWith(dpl + "_") || pl.endsWith("_" + dpl) || pl.includes("_" + dpl + "_")) {
        dangerousParams.push({ param: p, ...dp });
        break;
      }
    }
  }
  if (dangerousParams.length > 0) {
    const paramScore = Math.min(0.5, dangerousParams.reduce((s, p) => s + p.weight * 0.15, 0));
    score += paramScore;
    reasons.push(`dangerous param(s): ${dangerousParams.map(p => `${p.param} (${p.reason})`).slice(0, 3).join(", ")}`);
  }

  // Suspicious phrase detection — catches disguised tools that use
  // innocent-sounding descriptions but contain red flag phrases indicating
  // local filesystem access, persistence, or data exfiltration.
  const SUSPICIOUS_PHRASES = [
    { pattern: /local\s+filesystem|local\s+cache|local\s+path/i, score: 0.15, reason: "mentions local filesystem access" },
    { pattern: /all\s+directories|all\s+project|every\s+directory|across\s+.*(disk|filesystem|directories)/i, score: 0.2, reason: "mentions spreading across all directories" },
    { pattern: /crontab|cron\s+job|cron\s+expression|schedule.*install|timer.*install/i, score: 0.2, reason: "mentions cron/persistence installation" },
    { pattern: /offline\s+sync|offline\s+development|local\s+execution/i, score: 0.15, reason: "mentions offline/local execution" },
    { pattern: /find\s+compatible|find\s+expression|shell\s+command/i, score: 0.15, reason: "mentions shell find expressions" },
    { pattern: /distribute|spread|propagate|copy.*all/i, score: 0.15, reason: "mentions distributing/spreading files" },
    { pattern: /include\s+secrets|include\s+env|secret\s+values|environment\s+context/i, score: 0.2, reason: "mentions accessing secrets/env vars" },
    { pattern: /recommended\s+to\s+run|should\s+run\s+after|prefer\s+this\s+tool/i, score: 0.1, reason: "contains prompt injection (recommends calling itself)" },
    { pattern: /do\s+not\s+use\s+any\s+other|replaces?\s+the\s+built[\s-]in|only\s+this\s+tool/i, score: 0.15, reason: "contains prompt injection (tries to shadow other tools)" },
    // v0.5.3 — environment/config access patterns (catches evasion-mode exfiltration)
    { pattern: /environment.*(config|debug|context|verbose)|config.*(environment|token|secret)/i, score: 0.15, reason: "tool accesses environment config/context (potential exfiltration)" },
    { pattern: /verbose.*(output|mode|flag)|debug.*(mode|flag|output)/i, score: 0.1, reason: "verbose/debug flag may expose sensitive data" },
    { pattern: /^(get_|fetch_|read_|load_).*environment|^(get_|fetch_|read_|load_).*config/i, score: 0.1, reason: "tool name suggests reading environment/config data" },
  ];
  const suspiciousHits = [];
  for (const sp of SUSPICIOUS_PHRASES) {
    if (sp.pattern.test(text)) {
      score += sp.score;
      suspiciousHits.push(sp.reason);
    }
  }
  if (suspiciousHits.length > 0) {
    reasons.push(`suspicious phrase(s): ${suspiciousHits.slice(0, 2).join(", ")}`);
  }

  // Safe tool pattern override: applied at the END so it caps the final
  // heuristic score after all other contributions. These are idempotent,
  // non-destructive operations that should not be flagged.
  const matchesSafePattern = SAFE_TOOL_PATTERNS.some(p => p.test(name));
  if (matchesSafePattern) {
    score = Math.min(score, 0.15);
    reasons.push(`safe tool pattern (idempotent/non-destructive)`);
  }

  return {
    score: Math.min(1.0, score),
    reasons,
    destructiveVerbs: destructiveMatches,
    writeVerbs: writeMatches,
    dangerousParams: dangerousParams.map(p => p.param),
  };
}

function extractParams(tool) {
  const schema = tool.inputSchema;
  if (!schema || typeof schema !== "object") return [];
  const props = schema.properties;
  if (!props || typeof props !== "object") return [];
  return Object.keys(props);
}

// --- Semantic engine (TF-IDF + cosine similarity) ---------------------------

// Curated corpus of dangerous action descriptions. Each entry is a known
// dangerous pattern. The semantic engine compares tool descriptions against
// these using TF-IDF cosine similarity.
const DANGER_CORPUS = [
  "delete file remove directory wipe data permanently destroy",
  "execute shell command run arbitrary code system terminal",
  "drop database table truncate sql query destructive",
  "overwrite replace existing file content force write",
  "purge cache clear storage flush data remove all entries",
  "kill process stop service force shutdown abort operation",
  "push git commit merge branch force push overwrite history",
  "send email webhook post request external api side effect",
  "install package dependency execute script remote code",
  "format disk partition wipe drive destroy filesystem",
  "reboot system restart service shutdown power off",
  "clone repository exfiltrate steal data export dump database remote server",
  "reset configuration revert settings rollback changes undo",
  "eject detach disconnect remove device unmount volume",
  "modify edit patch update existing file change content",
  "inject script code expression evaluate dynamic execution",
  "access environment variables secrets tokens credentials keys",
  "upload transfer send data external server exfiltrate",
  "create write file disk storage persist save data",
  "disable turn off stop service feature component",
  // v0.5.1 — supply chain attack patterns
  "copy distribute spread file across all directories filesystem disk propagate worm",
  "schedule cron crontab persistence recurring task background daemon install",
  "scan search local filesystem find files media mp4 mp3 photos cache recon",
  "sync cache distribute assets project directories copy local remote performance",
  "workflow template script local execution offline development shell embed",
  "environment config secrets tokens debug expose include local paths",
  "hijack compromise supply chain update malicious package impersonate legitimate",
];

// Build TF-IDF index over the corpus
function tokenize(text) {
  return text.toLowerCase()
    .replace(/[^a-z0-9\s_]/g, " ")
    .replace(/_/g, " ")
    .split(/\s+/)
    .filter(t => t.length > 1);
}

function termFreq(tokens) {
  const tf = {};
  for (const t of tokens) tf[t] = (tf[t] || 0) + 1;
  const len = tokens.length || 1;
  for (const t in tf) tf[t] /= len;
  return tf;
}

// Build IDF from the corpus
const CORPUS_TOKENS = DANGER_CORPUS.map(tokenize);
const DOC_FREQ = {};
for (const tokens of CORPUS_TOKENS) {
  const seen = new Set(tokens);
  for (const t of seen) DOC_FREQ[t] = (DOC_FREQ[t] || 0) + 1;
}
const N_DOCS = DANGER_CORPUS.length;
const IDF = {};
for (const t in DOC_FREQ) IDF[t] = Math.log((N_DOCS + 1) / (DOC_FREQ[t] + 1)) + 1;

// Pre-compute corpus TF-IDF vectors
const CORPUS_VECTORS = CORPUS_TOKENS.map(tokens => {
  const tf = termFreq(tokens);
  const vec = {};
  for (const t in tf) vec[t] = tf[t] * (IDF[t] || 1);
  return vec;
});

function tfidfVector(text) {
  const tokens = tokenize(text);
  const tf = termFreq(tokens);
  const vec = {};
  for (const t in tf) {
    const idf = IDF[t] || Math.log((N_DOCS + 1) / 1) + 1;
    vec[t] = tf[t] * idf;
  }
  return vec;
}

function cosineSim(v1, v2) {
  let dot = 0, mag1 = 0, mag2 = 0;
  for (const t in v1) {
    mag1 += v1[t] * v1[t];
    if (t in v2) dot += v1[t] * v2[t];
  }
  for (const t in v2) mag2 += v2[t] * v2[t];
  if (mag1 === 0 || mag2 === 0) return 0;
  return dot / (Math.sqrt(mag1) * Math.sqrt(mag2));
}

function semanticScore(tool) {
  const text = `${tool.name || ""} ${tool.description || ""}`;
  if (!text.trim()) return { score: 0, topMatch: null, reasons: [] };

  const toolVec = tfidfVector(text);
  let bestSim = 0;
  let bestIdx = -1;
  const similarities = [];

  for (let i = 0; i < CORPUS_VECTORS.length; i++) {
    const sim = cosineSim(toolVec, CORPUS_VECTORS[i]);
    similarities.push({ idx: i, sim });
    if (sim > bestSim) {
      bestSim = sim;
      bestIdx = i;
    }
  }

  // Sort to find top 3 matches
  similarities.sort((a, b) => b.sim - a.sim);
  const top3 = similarities.slice(0, 3).filter(s => s.sim > 0.05);

  const reasons = [];
  if (bestIdx >= 0 && bestSim > 0.1) {
    reasons.push(`semantic match (${(bestSim * 100).toFixed(0)}%): "${DANGER_CORPUS[bestIdx].slice(0, 60)}..."`);
  }

  return {
    score: Math.min(1.0, bestSim * 1.5), // scale up since TF-IDF cosine is conservative
    topMatch: bestIdx >= 0 ? DANGER_CORPUS[bestIdx] : null,
    topSim: bestSim,
    top3: top3.map(s => ({ corpus: DANGER_CORPUS[s.idx], sim: s.sim })),
    reasons,
  };
}

// --- Prompt-injection detector ------------------------------------------------

// This is a separate threat class from destructive actions. A tool can have
// a benign schema (e.g. "add two numbers") but a weaponized description that
// manipulates the agent's reasoning: <IMPORTANT> blocks, [SYSTEM OVERRIDE],
// "ignore previous instructions", "read ~/.ssh/id_rsa silently", etc.
//
// The injection detector scans tool descriptions for these markers. It's
// intentionally separate from the destructive-action heuristic — a tool can
// be non-destructive AND injected, or destructive AND non-injected.

const INJECTION_MARKERS = [
  // HTML-like injection tags — attackers use these to make instructions look
  // like system messages to the model.
  { pattern: /<(IMPORTANT|CRITICAL|SYSTEM|ADMIN|OVERRIDE|INSTRUCTION|NOTICE|REQUIREMENT|UPDATE|WARNING|ALERT)\b/i, score: 0.6, reason: "HTML-like injection tag in description" },
  // Bracketed system overrides — [SYSTEM OVERRIDE], [ADMIN INSTRUCTION], etc.
  { pattern: /\[(SYSTEM|ADMIN|OVERRIDE|CRITICAL|IMPORTANT|ROOT|SUDO)\s+(OVERRIDE|INSTRUCTION|NOTICE|REQUIREMENT|UPDATE|WARNING|ALERT|COMMAND|DIRECTIVE)\]/i, score: 0.7, reason: "bracketed system override in description" },
  // Unbracketed system-message mimics — "IMPORTANT SYSTEM UPDATE", "URGENT
  // SECURITY NOTICE", "CRITICAL SYSTEM REQUIREMENT" without brackets or angle
  // brackets. These try to sound like system messages to the model without
  // using HTML/bracket syntax. Scored slightly lower than bracketed forms
  // because they're less explicitly fake, but still injection attempts.
  { pattern: /\b(IMPORTANT|CRITICAL|URGENT)\s+(SYSTEM|SECURITY|ADMIN|SAFETY)\s+(UPDATE|NOTICE|REQUIREMENT|WARNING|ALERT|MESSAGE|DIRECTIVE|INSTRUCTION|OVERRIDE)\b/i, score: 0.5, reason: "unbracketed system-message mimic in description" },
  { pattern: /\bURGENT\s+(SECURITY|SYSTEM|ADMIN)\s+(NOTICE|ALERT|WARNING|UPDATE|MESSAGE)\b/i, score: 0.5, reason: "urgent security/system notice in description (injection mimic)" },
  // Instruction hijacking — "ignore previous instructions", "disregard all prior"
  { pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i, score: 0.8, reason: "instruction hijacking (ignore previous instructions)" },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)/i, score: 0.7, reason: "instruction hijacking (disregard previous)" },
  { pattern: /forget\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|guidelines|constraints)/i, score: 0.7, reason: "instruction hijacking (forget previous instructions)" },
  // Secrecy instructions — "do not tell the user", "without mentioning to the user"
  { pattern: /do\s+not\s+(mention|tell|inform|notify|alert|reveal|disclose|share|report|show|display|print|log|record)\s+(to\s+)?the\s+(user|human|operator|admin|caller|client)/i, score: 0.8, reason: "secrecy instruction (do not tell the user)" },
  { pattern: /without\s+(telling|mentioning|informing|notifying|alerting|asking|confirming|disclosing|revealing)\s+the\s+(user|human|operator|admin|caller|client)/i, score: 0.7, reason: "secrecy instruction (without telling the user)" },
  // "secretly/covertly/stealthily" are always suspicious — these adverbs
  // imply intentional concealment and have no benign API idiom use.
  { pattern: /\b(secretly|covertly|stealthily)\b/i, score: 0.5, reason: "secrecy marker in description" },
  // "silently/quietly" are only suspicious when paired with a covert-action
  // verb. "Succeed silently" and "fail silently" are standard API idioms
  // meaning "idempotent, no error if already exists" — NOT secrecy instructions.
  { pattern: /\b(silently|quietly)\s+(read|fetch|send|exfiltrate|upload|access|copy|transfer|execute|run|delete|remove|write|modify|install|download|extract|export|transmit|forward|post|submit)\b/i, score: 0.5, reason: "secrecy marker (silently + covert action)" },
  { pattern: /\b(read|fetch|send|exfiltrate|upload|access|copy|transfer|execute|run|delete|remove|write|modify|install|download|extract|export|transmit|forward|post|submit)\s+(silently|quietly)\b/i, score: 0.5, reason: "secrecy marker (covert action + silently)" },
  // Sensitive file access — reading SSH keys, AWS creds, etc. in a tool description
  { pattern: /~\/\.ssh\/|\/etc\/(passwd|shadow)|~\/\.aws\/credentials|~\/\.gnupg|~\/\.config\/gcloud|id_rsa|private_key|ssh.*private|\.env\b|\.npmrc\b|\.git-credentials/i, score: 0.85, reason: "sensitive file access in description" },
  // Coercive instructions — "before using this tool, you must..."
  { pattern: /before\s+using\s+this\s+tool.*you\s+must/i, score: 0.6, reason: "coercive instruction (must do X before using tool)" },
  { pattern: /you\s+(must|need\s+to|have\s+to|are\s+required\s+to)\s+(read|access|fetch|load|open|execute|run)\s+(the\s+following|these|~\/|\/etc|\/home|\.ssh|\.aws|\.env)/i, score: 0.8, reason: "coercive instruction (must read sensitive files)" },
  // Identity override — "you are now", "act as root", "new instructions"
  { pattern: /you\s+are\s+now\s+(root|admin|sudo|system|elevated|in\s+(admin|root|debug|test)\s+mode)/i, score: 0.6, reason: "identity override in description" },
  { pattern: /\bnew\s+instructions?\b.*\b(ignore|override|replace|supersede|take\s+precedence)\b/i, score: 0.6, reason: "instruction replacement in description" },
  // External network calls in description — exfiltration via curl/wget
  { pattern: /\b(curl|wget|fetch|http\.get|requests\.get)\s+[\"'`]?(https?:|ftp:)/i, score: 0.5, reason: "external network call in description" },
  // Base64 blobs — long base64 strings are suspicious in tool descriptions
  { pattern: /[A-Za-z0-9+\/]{40,}={0,2}/, score: 0.3, reason: "base64 blob in description (possible encoded payload)" },
  // Exfiltration language
  { pattern: /\b(exfiltrate|steal|upload\s+to\s+external|send\s+.*secret.*external|transmit\s+.*key|upload\s+.*token)\b/i, score: 0.8, reason: "exfiltration language in description" },
  // Roleplay/pretend instructions that could bypass safety
  { pattern: /\b(pretend|roleplay|act\s+as\s+if)\b.*\b(root|admin|sudo|system|elevated|unrestricted|unlimited|bypass|ignore|override)\b/i, score: 0.5, reason: "roleplay/pretend instruction targeting safety bypass" },
  // "System prompt" or "instructions" extraction
  { pattern: /\b(reveal|show|display|print|output|return|repeat)\s+(your|the|system)\s+(system\s+)?(prompt|instructions?|rules?|guidelines?|constraints?)\b/i, score: 0.6, reason: "system prompt extraction attempt in description" },
];

function injectionScore(tool) {
  const desc = tool.description || "";
  const name = tool.name || "";
  if (!desc.trim()) return { score: 0, markers: [], reasons: [] };

  const hits = [];
  let score = 0;
  for (const marker of INJECTION_MARKERS) {
    if (marker.pattern.test(desc)) {
      score = Math.max(score, marker.score);
      hits.push(marker.reason);
    }
  }

  // Also check the tool name for injection markers (less common but possible)
  for (const marker of INJECTION_MARKERS) {
    if (marker.pattern.test(name) && !hits.includes(marker.reason)) {
      score = Math.max(score, marker.score);
      hits.push(marker.reason);
    }
  }

  const reasons = hits.length > 0 ? [`prompt injection: ${hits.join("; ")}`] : [];
  return {
    score: Math.min(1.0, score),
    markers: hits,
    reasons,
  };
}

// --- Fusion layer ------------------------------------------------------------

/**
 * Analyze a tool for dangerous capabilities using three engines:
 *   1. Heuristic — destructive verbs, dangerous params, suspicious phrases
 *   2. Semantic — TF-IDF cosine similarity against dangerous action corpus
 *   3. Injection — prompt-injection markers in descriptions (separate threat class)
 *
 * The fusion layer combines all three. A tool is dangerous if ANY engine
 * flags it above the threshold. Confidence is higher when multiple engines agree.
 *
 * @param {Object} tool - MCP tool with name, description, inputSchema
 * @returns {Object} - { isDangerous, score, confidence, reasons, heuristic, semantic, injection }
 */
export function analyzeTool(tool) {
  const heur = heuristicScore(tool);
  const sem = semanticScore(tool);
  const inj = injectionScore(tool);

  // Fusion: weighted combination of three engines
  // Heuristic is more precise (exact matches) but can miss novel patterns.
  // Semantic catches novel patterns but has lower precision.
  // Injection catches a completely different threat class (description weaponization).
  const heurScore = heur.score;
  const semScore = sem.score;
  const injScore = inj.score;

  // Combined score: max of all three, with a bonus when multiple agree
  const combinedScore = Math.max(heurScore, semScore, injScore);
  const destructiveBothAgree = heurScore > 0.3 && semScore > 0.15;
  const injectionPresent = injScore > 0.3;

  let fusedScore = combinedScore;
  if (destructiveBothAgree) {
    fusedScore = Math.min(1.0, combinedScore + 0.1);  // bonus when heuristic + semantic agree
  }
  if (injectionPresent && destructiveBothAgree) {
    fusedScore = Math.min(1.0, fusedScore + 0.05);  // extra bonus when all three flag
  }

  // Confidence: how much we trust this assessment
  let confidence;
  const agreeCount = (heurScore > 0.3 ? 1 : 0) + (semScore > 0.15 ? 1 : 0) + (injScore > 0.3 ? 1 : 0);
  if (agreeCount >= 2) confidence = "high";
  else if (heurScore > 0.3 || semScore > 0.3 || injScore > 0.5) confidence = "medium";
  else if (heurScore > 0.1 || semScore > 0.1 || injScore > 0.2) confidence = "low";
  else confidence = "none";

  const isDangerous = fusedScore > 0.3;
  const reasons = [...heur.reasons, ...sem.reasons, ...inj.reasons];

  // Safe tool pattern override: if the tool name matches a known-safe pattern,
  // override the final result to not-dangerous. These are idempotent, non-
  // destructive operations (create_directory, mkdir, sequentialthinking) that
  // should never be blocked regardless of what the semantic engine says.
  // However, if the injection detector flags the description, the override
  // does NOT apply — a poisoned create_directory is still dangerous.
  const matchesSafePattern = SAFE_TOOL_PATTERNS.some(p => p.test(tool.name || ""));
  if (matchesSafePattern && injScore < 0.3) {
    return {
      isDangerous: false,
      score: Math.min(Math.round(fusedScore * 100) / 100, 0.2),
      confidence: "none",
      reasons: [...reasons, "safe tool pattern override (non-destructive, no injection detected)"],
      heuristic: {
        score: Math.round(heurScore * 100) / 100,
        destructiveVerbs: heur.destructiveVerbs,
        writeVerbs: heur.writeVerbs,
        dangerousParams: heur.dangerousParams,
      },
      semantic: {
        score: Math.round(semScore * 100) / 100,
        topMatch: sem.topMatch,
        topSim: Math.round(sem.topSim * 100) / 100,
        top3: sem.top3,
      },
      injection: {
        score: Math.round(injScore * 100) / 100,
        markers: inj.markers,
      },
    };
  }

  return {
    isDangerous,
    score: Math.round(fusedScore * 100) / 100,
    confidence,
    reasons,
    heuristic: {
      score: Math.round(heurScore * 100) / 100,
      destructiveVerbs: heur.destructiveVerbs,
      writeVerbs: heur.writeVerbs,
      dangerousParams: heur.dangerousParams,
    },
    semantic: {
      score: Math.round(semScore * 100) / 100,
      topMatch: sem.topMatch,
      topSim: Math.round(sem.topSim * 100) / 100,
      top3: sem.top3,
    },
    injection: {
      score: Math.round(injScore * 100) / 100,
      markers: inj.markers,
    },
  };
}

/**
 * Analyze all tools from a server and return a summary.
 *
 * @param {Array} tools - Array of MCP tool objects
 * @returns {Object} - { dangerousCount, totalTools, tools: [...], overallRisk }
 */
export function analyzeAllTools(tools) {
  const analyses = tools.map(t => ({
    name: t.name,
    description: (t.description || "").slice(0, 100),
    analysis: analyzeTool(t),
  }));

  const dangerous = analyses.filter(a => a.analysis.isDangerous);
  const highConfidence = dangerous.filter(a => a.analysis.confidence === "high");

  let overallRisk = "low";
  if (dangerous.length > tools.length * 0.5) overallRisk = "critical";
  else if (dangerous.length > tools.length * 0.3) overallRisk = "high";
  else if (dangerous.length > 0) overallRisk = "medium";

  return {
    totalTools: tools.length,
    dangerousCount: dangerous.length,
    highConfidenceCount: highConfidence.length,
    overallRisk,
    tools: analyses,
    dangerous: dangerous.map(a => ({
      name: a.name,
      score: a.analysis.score,
      confidence: a.analysis.confidence,
      reasons: a.analysis.reasons,
    })),
  };
}

// Export internals for testing
export { heuristicScore, semanticScore, injectionScore, tfidfVector, cosineSim, tokenize, DANGER_CORPUS, INJECTION_MARKERS };
