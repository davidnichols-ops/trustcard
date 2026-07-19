// RFC 8785 (JSON Canonicalization Scheme, JCS) — dependency-free implementation.
// Every trustcard digest is computed over JCS output so that two parties can
// reproduce the exact same bytes for the same logical JSON value.

// JCS string escaping: only the mandatory JSON escapes, using shortest form.
const ESCAPES = {
  "\b": "\\b",
  "\t": "\\t",
  "\n": "\\n",
  "\f": "\\f",
  "\r": "\\r",
  '"': '\\"',
  "\\": "\\\\",
};

function serializeString(s) {
  let out = '"';
  for (const ch of s) {
    const esc = ESCAPES[ch];
    if (esc) {
      out += esc;
    } else {
      const cp = ch.codePointAt(0);
      if (cp < 0x20) {
        out += "\\u" + cp.toString(16).padStart(4, "0");
      } else {
        out += ch; // JCS: emit all other characters literally (UTF-8/16, no \uXXXX)
      }
    }
  }
  return out + '"';
}

// JCS number serialization per ECMAScript Number::toString, with the
// canonicalization notes from RFC 8785 §3.2.2.3:
//   - no -0, no trailing ".0", exponent written as e±n (no leading zeros,
//     no plus sign on negative exponents is required; '+' kept off positive),
//   - ECMAScript switches to exponential at >= 1e21 and <= 1e-7.
function serializeNumber(n) {
  if (!Number.isFinite(n)) {
    throw new TypeError(`JCS cannot serialize non-finite number: ${n}`);
  }
  if (Object.is(n, -0)) n = 0;
  if (Number.isInteger(n) && Math.abs(n) < 1e21) {
    return n.toString(10);
  }
  // Use JS shortest round-trip representation, then normalize exponent form.
  // JCS keeps the ECMAScript "e+21"/"e-7" convention: '+' on positive
  // exponents, '-' on negative, no leading zeros in the exponent.
  let s = String(n); // e.g. "1e+21", "1.5e-7", "3.14"
  if (s.includes("e") || s.includes("E")) {
    let [mantissa, exp] = s.toLowerCase().split("e");
    let sign = "+";
    if (exp.startsWith("+")) exp = exp.slice(1);
    else if (exp.startsWith("-")) { sign = "-"; exp = exp.slice(1); }
    exp = exp.replace(/^0+/, "") || "0";
    if (mantissa.endsWith(".0")) mantissa = mantissa.slice(0, -2);
    return `${mantissa}e${sign}${exp}`;
  }
  if (s.endsWith(".0")) s = s.slice(0, -2);
  return s;
}

// Serialize any JSON value to its canonical byte sequence (as a JS string).
// Rejects values that are not representable in JSON.
export function canon(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") return serializeNumber(value);
  if (t === "string") return serializeString(value);
  if (t === "object") {
    if (Array.isArray(value)) {
      return "[" + value.map((v) => canon(v === undefined ? null : v)).join(",") + "]";
    }
    // JCS sorts object keys by UTF-16 code units — the default JS string sort.
    const keys = Object.keys(value).filter((k) => value[k] !== undefined && typeof value[k] !== "function" && typeof value[k] !== "symbol");
    keys.sort();
    return (
      "{" +
      keys.map((k) => serializeString(k) + ":" + canon(value[k])).join(",") +
      "}"
    );
  }
  throw new TypeError(`JCS cannot serialize value of type ${t}`);
}

// Structural deep-equality on JSON values (key-order insensitive).
export function jsonEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    return a.length === b.length && a.every((v, i) => jsonEqual(v, b[i]));
  }
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => Object.prototype.hasOwnProperty.call(b, k) && jsonEqual(a[k], b[k]));
}
