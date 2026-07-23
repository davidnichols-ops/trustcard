// Auth: OAuth 2.1 token introspection + built-in dev issuer + scope matching.
//
// This module provides the auth layer for MCP tool calls. It supports two
// token sources:
//
//   1. External IdP — any OAuth 2.1 provider (Auth0, Okta, Keycloak, GitHub).
//      trustcard does RFC 7662 token introspection (POST to the introspection
//      endpoint with the token). The response is cached for the token's
//      lifetime or a configurable TTL.
//
//   2. Built-in dev issuer — a lightweight JWT-based token issuer for local
//      development. It signs tokens with an Ed25519 or HMAC key and validates
//      them locally. NOT for production — no refresh tokens, no revocation
//      endpoint, no PKCE flow. It exists so developers can test scope-based
//      enforcement without standing up an IdP.
//
// Scope model:
//   Scopes are strings: "read:files", "write:db", "admin", etc.
//   A tool's manifest entry declares requiredScopes: ["read:files"].
//   A token has grantedScopes: ["read:files", "write:db"].
//   The check is: every required scope must be present in the granted set.
//   Wildcard scopes ("*" or "read:*") are supported.

import { createHash, createHmac, randomBytes, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";

// --- Scope matching ---------------------------------------------------------

/**
 * Check if a granted scope set satisfies a required scope.
 * Supports wildcards: "*" matches everything, "read:*" matches "read:files".
 */
export function scopeSatisfies(granted, required) {
  const g = new Set(Array.isArray(granted) ? granted : [granted]);
  const r = Array.isArray(required) ? required : [required];

  for (const need of r) {
    if (!hasScope(g, need)) return false;
  }
  return true;
}

function hasScope(grantedSet, scope) {
  if (grantedSet.has("*")) return true;
  if (grantedSet.has(scope)) return true;
  // Wildcard: "read:*" matches "read:files", "read:db", etc.
  if (scope.includes(":")) {
    const prefix = scope.split(":")[0] + ":*";
    if (grantedSet.has(prefix)) return true;
  }
  // Check all granted wildcards
  for (const g of grantedSet) {
    if (g.endsWith(":*") && scope.startsWith(g.slice(0, -1))) return true;
  }
  return false;
}

// --- Token representation ---------------------------------------------------

/**
 * A validated token. This is the internal representation after introspection
 * or local verification — never the raw token string.
 */
export class AuthToken {
  constructor({ subject, scopes, expiresAt, issuer, active = true, metadata = {} }) {
    this.subject = subject;       // agent ID or user ID
    this.scopes = scopes ?? [];   // granted scopes
    this.expiresAt = expiresAt;   // ISO timestamp or null (no expiry)
    this.issuer = issuer;         // who issued the token
    this.active = active;         // introspection result
    this.metadata = metadata;     // anything else from introspection
  }

  get isExpired() {
    if (!this.expiresAt) return false;
    return Date.parse(this.expiresAt) < Date.now();
  }

  get isValid() {
    return this.active && !this.isExpired;
  }

  canCall(requiredScopes) {
    return this.isValid && scopeSatisfies(this.scopes, requiredScopes);
  }
}

// --- Built-in dev issuer ----------------------------------------------------

/**
 * Issue a dev-mode JWT-like token. Uses HMAC-SHA256 for simplicity.
 * The token is base64url(header).base64url(payload).base64url(sig).
 *
 * This is NOT a real OAuth server. No refresh tokens, no authorization code
 * flow, no PKCE. It's for local development and testing only.
 */
export class DevIssuer {
  constructor({ secret = null, issuer = "trustcard-dev" } = {}) {
    this.secret = secret ?? randomBytes(32).toString("hex");
    this.issuer = issuer;
  }

  issue({ subject, scopes, expiresInSeconds = 3600 }) {
    const header = { alg: "HS256", typ: "JWT+trustcard" };
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      sub: subject,
      scope: (scopes ?? []).join(" "),
      iss: this.issuer,
      iat: now,
      exp: expiresInSeconds ? now + expiresInSeconds : null,
    };
    const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
    const data = `${enc(header)}.${enc(payload)}`;
    const sig = createHmac("sha256", this.secret).update(data).digest("base64url");
    return `${data}.${sig}`;
  }

  verify(token) {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, sigB64] = parts;
    const data = `${headerB64}.${payloadB64}`;
    const expectedSig = createHmac("sha256", this.secret).update(data).digest("base64url");
    if (sigB64 !== expectedSig) return null;

    let payload;
    try {
      payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    } catch {
      return null;
    }

    if (payload.iss !== this.issuer) return null;

    const expiresAt = payload.exp ? new Date(payload.exp * 1000).toISOString() : null;
    return new AuthToken({
      subject: payload.sub,
      scopes: (payload.scope ?? "").split(" ").filter(Boolean),
      expiresAt,
      issuer: payload.iss,
      active: true,
      metadata: { iat: payload.iat },
    });
  }
}

// --- External IdP introspection (RFC 7662) ----------------------------------

/**
 * Introspect a token against an OAuth 2.1 provider's introspection endpoint.
 * Caches results until the token expires or the cache TTL elapses.
 *
 * config:
 *   introspectionEndpoint — URL (e.g. "https://your-idp/oauth/introspect")
 *   clientId              — optional, for authenticated introspection
 *   clientSecret          — optional, for authenticated introspection
 *   cacheTtlSeconds       — default 60, how long to cache active results
 */
export class IdpIntrospector {
  constructor({ introspectionEndpoint, clientId = null, clientSecret = null, cacheTtlSeconds = 60 } = {}) {
    if (!introspectionEndpoint) throw new Error("IdpIntrospector: introspectionEndpoint is required");
    this.introspectionEndpoint = introspectionEndpoint;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.cacheTtlSeconds = cacheTtlSeconds;
    this.cache = new Map(); // token -> { authToken, cachedAt }
  }

  async introspect(token) {
    // Check cache
    const cached = this.cache.get(token);
    if (cached) {
      const age = (Date.now() - cached.cachedAt) / 1000;
      if (age < this.cacheTtlSeconds && cached.authToken?.isValid) {
        return cached.authToken;
      }
      this.cache.delete(token);
    }

    // RFC 7662: POST application/x-www-form-urlencoded with token=value
    const body = new URLSearchParams({ token });
    const headers = { "Content-Type": "application/x-www-form-urlencoded" };

    // Authenticated introspection (client credentials)
    if (this.clientId && this.clientSecret) {
      const cred = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
      headers["Authorization"] = `Basic ${cred}`;
    }

    const resp = await fetch(this.introspectionEndpoint, {
      method: "POST",
      headers,
      body,
    });

    if (!resp.ok) {
      throw new Error(`introspection failed: HTTP ${resp.status} ${resp.statusText}`);
    }

    const data = await resp.json();

    // RFC 7662 response: { active, scope, exp, sub, iss, ... }
    if (!data.active) {
      return new AuthToken({ active: false, subject: null, scopes: [], issuer: data.iss ?? null });
    }

    const expiresAt = data.exp ? new Date(data.exp * 1000).toISOString() : null;
    const authToken = new AuthToken({
      active: true,
      subject: data.sub ?? data.username ?? null,
      scopes: (data.scope ?? "").split(" ").filter(Boolean),
      expiresAt,
      issuer: data.iss ?? null,
      metadata: data,
    });

    // Cache
    this.cache.set(token, { authToken, cachedAt: Date.now() });
    return authToken;
  }
}

// --- Token extraction from MCP requests -------------------------------------

/**
 * Extract a bearer token from an MCP tools/call request.
 *
 * MCP clients can pass auth in two places:
 *   1. The _meta field on the request: { _meta: { auth: { token: "..." } } }
 *   2. An environment variable that the proxy reads (e.g. MCP_AUTH_TOKEN)
 *
 * Returns the raw token string or null.
 */
export function extractToken(request, envVar = "MCP_AUTH_TOKEN") {
  // Check _meta.auth.token first (per-call token)
  const metaToken = request?.params?._meta?.auth?.token;
  if (metaToken) return metaToken;

  // Check _meta.authorization (Bearer header style)
  const authz = request?.params?._meta?.authorization;
  if (authz && authz.startsWith("Bearer ")) {
    return authz.slice(7);
  }

  // Fall back to environment variable (session-level token)
  if (process.env[envVar]) return process.env[envVar];

  return null;
}

/**
 * Strip auth metadata from a request before forwarding to the server.
 * The server should not see the trustcard-internal auth fields.
 */
export function stripAuth(request) {
  if (!request?.params?._meta) return request;
  const cleaned = { ...request, params: { ...request.params } };
  cleaned._meta = { ...request.params._meta };
  delete cleaned._meta.auth;
  delete cleaned._meta.authorization;
  if (Object.keys(cleaned._meta).length === 0) delete cleaned._meta;
  cleaned.params._meta = cleaned._meta;
  return cleaned;
}

// --- Combined validator -----------------------------------------------------

/**
 * A validator that knows how to handle both dev-issued and IdP tokens.
 * Tries local verification first (fast), falls back to introspection.
 */
export class TokenValidator {
  constructor({ devIssuer = null, idpIntrospector = null } = {}) {
    this.devIssuer = devIssuer;
    this.idpIntrospector = idpIntrospector;
  }

  async validate(token) {
    if (!token) return null;

    // Try dev issuer first (local, fast, no network)
    if (this.devIssuer) {
      const local = this.devIssuer.verify(token);
      if (local) return local;
    }

    // Fall back to IdP introspection
    if (this.idpIntrospector) {
      return await this.idpIntrospector.introspect(token);
    }

    return null;
  }
}
