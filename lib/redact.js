// Secret redaction utility — used by both stdio and HTTP proxies to prevent
// secrets from leaking into stderr logs, error messages, or debug output.
// Patterns cover common secret formats across major providers.

const REDACT_PATTERNS = [
  // GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
  [/gh[pousr]_[A-Za-z0-9]{16,}/g, "ghp_***REDACTED***"],
  // OpenAI API keys
  [/sk-[A-Za-z0-9]{16,}/g, "sk-***REDACTED***"],
  // Slack tokens
  [/xox[baprs]-[A-Za-z0-9-]{10,}/g, "xox-***REDACTED***"],
  // AWS access keys
  [/AKIA[0-9A-Z]{12,}/g, "AKIA***REDACTED***"],
  // Google API keys
  [/AIza[0-9A-Za-z_-]{20,}/g, "AIza***REDACTED***"],
  // Bearer tokens (any)
  [/Bearer\s+[A-Za-z0-9_.-]{20,}/g, "Bearer ***REDACTED***"],
  // JWT tokens
  [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "eyJ***REDACTED***"],
  // Generic high-entropy strings that look like API keys (40+ chars, alphanumeric + -_)
  // Only match in key-value contexts to avoid false positives on regular text
  [/(?:token|key|secret|password|passwd|credential|api_key|apikey|auth)["\s]*[:=]\s*["']?([A-Za-z0-9_\-]{40,})["']?/gi, (match) => match.replace(/[A-Za-z0-9_\-]{20,}$/, "***REDACTED***")],
];

// Redact known secret patterns from a string.
// Returns the string with secrets replaced by ***REDACTED***.
export function redact(text) {
  if (!text || typeof text !== "string") return text;
  let result = text;
  for (const [pattern, replacement] of REDACT_PATTERNS) {
    result = result.replace(pattern, replacement);
  }
  return result;
}

// Redact env vars that look like secrets (key names containing token, key, secret, etc.)
// Returns a new object with secret values replaced.
export function redactEnv(env) {
  const SECRET_KEY_PATTERNS = /token|key|secret|password|passwd|credential|api_key|apikey|auth/i;
  const result = {};
  for (const [k, v] of Object.entries(env)) {
    if (SECRET_KEY_PATTERNS.test(k) && v && v.length > 8) {
      result[k] = "***REDACTED***";
    } else {
      result[k] = v;
    }
  }
  return result;
}
