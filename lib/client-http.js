// MCP HTTP/SSE client — speaks the streamable-http and SSE transports.
// No dependencies — uses fetch() + EventSource (Node 18+ has both).
//
// The MCP "streamable-http" transport (2025-06-18) works as follows:
//   1. Client POSTs JSON-RPC requests to the endpoint URL.
//   2. Server responds with either:
//      a. application/json — a single JSON-RPC response, or
//      b. text/event-stream — SSE stream of JSON-RPC responses/notifications.
//   3. For SSE-only servers (older transport), client GETs the endpoint
//      to open the SSE stream, then POSTs requests separately.
//
// This client implements both patterns. It matches the McpStdioClient
// interface so checks.js / observe.js can use either transport transparently.

import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";

export class McpHttpClient {
  constructor({ url, transport = "streamable-http", headers = {}, timeout = 45_000 } = {}) {
    if (!url) throw new Error("McpHttpClient requires a url");
    this.url = url;
    this.transport = transport; // "streamable-http" or "sse"
    this.headers = { ...headers };
    this.timeout = timeout;
    this.pending = new Map();
    this.nextId = 1;
    this.sessionId = null; // Mcp-Session-Id from server
    this.stderr = ""; // compatibility with McpStdioClient
    this.started = false;
    this.listeners = new Map(); // notification method -> Set<fn>
    this._sseController = null; // AbortController for SSE stream
    this._sseBuffer = "";
  }

  on(method, fn) {
    if (!this.listeners.has(method)) this.listeners.set(method, new Set());
    this.listeners.get(method).add(fn);
    return () => this.listeners.get(method)?.delete(fn);
  }

  async start() {
    // For SSE transport, open the event stream first via GET.
    if (this.transport === "sse") {
      await this._openSseStream();
    }
    // For streamable-http, nothing to do upfront — the first POST
    // will negotiate everything.
    this.started = true;
  }

  async _openSseStream() {
    // SSE transport: GET the endpoint to open a persistent event stream.
    // The server sends an "endpoint" event with the URL to POST requests to.
    this._sseController = new AbortController();
    const startTimer = setTimeout(() => this._sseController?.abort(), this.timeout);

    try {
      const resp = await fetch(this.url, {
        method: "GET",
        headers: { Accept: "text/event-stream", ...this.headers },
        signal: this._sseController.signal,
      });

      if (!resp.ok) {
        throw new Error(`SSE connection failed: ${resp.status} ${resp.statusText}`);
      }

      // Read the stream
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();

      (async () => {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            this._sseBuffer += decoder.decode(value, { stream: true });
            this._processSseBuffer();
          }
        } catch (e) {
          if (e.name !== "AbortError") {
            this.stderr += `SSE stream error: ${e.message}\n`;
          }
        }
      })();
    } catch (e) {
      throw new Error(`Failed to open SSE stream: ${e.message}`);
    } finally {
      clearTimeout(startTimer);
    }
  }

  _processSseBuffer() {
    // SSE events are separated by double newlines (handle CRLF too)
    this._sseBuffer = this._sseBuffer.replace(/\r\n/g, "\n");
    let idx;
    while ((idx = this._sseBuffer.indexOf("\n\n")) >= 0) {
      const raw = this._sseBuffer.slice(0, idx);
      this._sseBuffer = this._sseBuffer.slice(idx + 2);
      this._handleSseEvent(raw);
    }
  }

  _handleSseEvent(raw) {
    // Parse SSE event: lines starting with "data:" contain the payload
    const lines = raw.split("\n");
    let event = "message";
    let data = "";

    for (const line of lines) {
      if (line.startsWith("event:")) {
        event = line.slice(6).trim();
      } else if (line.startsWith("data:")) {
        data += line.slice(5).trim();
      }
    }

    if (event === "endpoint") {
      // Server tells us where to POST requests (may differ from SSE URL)
      try {
        const baseUrl = new URL(this.url);
        this._postUrl = new URL(data, baseUrl).href;
      } catch {
        this._postUrl = data;
      }
      return;
    }

    if (!data) return;

    try {
      const msg = JSON.parse(data);
      this._handleMessage(msg);
    } catch {
      // Not JSON — ignore
    }
  }

  _handleMessage(msg) {
    if (msg.id != null && this.pending.has(msg.id)) {
      const { resolve, reject } = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      if (msg.error) reject(msg.error);
      else resolve(msg.result);
      return;
    }

    // Notification (no id): dispatch to subscribers
    if (msg.method && this.listeners.has(msg.method)) {
      for (const fn of this.listeners.get(msg.method)) {
        try { fn(msg.params); } catch {}
      }
    }
  }

  async request(method, params, timeoutMs = 15_000) {
    const id = this.nextId++;
    const body = { jsonrpc: "2.0", id, method, params: params ?? {} };

    const postUrl = this._postUrl || this.url;
    const requestHeaders = {
      "Content-Type": "application/json",
      Accept: this.transport === "sse" ? "text/event-stream" : "application/json, text/event-stream",
      ...this.headers,
    };

    // Include session ID if we have one
    if (this.sessionId) {
      requestHeaders["Mcp-Session-Id"] = this.sessionId;
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout: ${method} (${timeoutMs}ms)`));
      }, timeoutMs);

      this.pending.set(id, {
        resolve: (r) => { clearTimeout(timer); resolve(r); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });

      fetch(postUrl, {
        method: "POST",
        headers: requestHeaders,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs + 5000),
      })
        .then(async (resp) => {
          // Capture session ID from response headers
          const sid = resp.headers.get("mcp-session-id");
          if (sid) this.sessionId = sid;

          if (!resp.ok) {
            const text = await resp.text().catch(() => "");
            const err = new Error(`HTTP ${resp.status}: ${text.slice(0, 200)}`);
            const { reject } = this.pending.get(id) || {};
            if (reject) {
              clearTimeout(timer);
              this.pending.delete(id);
              reject(err);
            }
            return;
          }

          const contentType = resp.headers.get("content-type") || "";

          if (contentType.includes("text/event-stream")) {
            // SSE response — read the stream for the response
            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let sseBuffer = "";

            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                sseBuffer += decoder.decode(value, { stream: true });

                // Process complete SSE events (handle both LF and CRLF)
                // Normalize CRLF to LF so the \n\n separator check works.
                sseBuffer = sseBuffer.replace(/\r\n/g, "\n");
                let idx;
                while ((idx = sseBuffer.indexOf("\n\n")) >= 0) {
                  const raw = sseBuffer.slice(0, idx);
                  sseBuffer = sseBuffer.slice(idx + 2);

                  // Extract data from SSE event
                  let data = "";
                  for (const line of raw.split("\n")) {
                    if (line.startsWith("data:")) {
                      data += line.slice(5).trim();
                    }
                  }

                  if (data) {
                    try {
                      const msg = JSON.parse(data);
                      this._handleMessage(msg);
                    } catch {}
                  }
                }
              }
            } catch (e) {
              // Stream ended or errored — if we still have a pending request, it timed out
            }
          } else if (contentType.includes("application/json")) {
            // Plain JSON response
            const result = await resp.json();
            this._handleMessage(result);
          } else {
            // Unknown content type — try to parse as JSON
            const text = await resp.text();
            try {
              const result = JSON.parse(text);
              this._handleMessage(result);
            } catch {
              const err = new Error(`Unexpected content-type: ${contentType}`);
              const { reject } = this.pending.get(id) || {};
              if (reject) {
                clearTimeout(timer);
                this.pending.delete(id);
                reject(err);
              }
            }
          }
        })
        .catch((e) => {
          const { reject } = this.pending.get(id) || {};
          if (reject) {
            clearTimeout(timer);
            this.pending.delete(id);
            reject(e);
          }
        });
    });
  }

  async notify(method, params, timeoutMs = 10_000) {
    const body = { jsonrpc: "2.0", method, params: params ?? {} };
    const postUrl = this._postUrl || this.url;
    const requestHeaders = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...this.headers,
    };

    if (this.sessionId) {
      requestHeaders["Mcp-Session-Id"] = this.sessionId;
    }

    try {
      await fetch(postUrl, {
        method: "POST",
        headers: requestHeaders,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(Math.max(1, Math.ceil(timeoutMs))),
      });
    } catch {
      // Notifications are fire-and-forget
    }
  }

  async stop() {
    // Close SSE stream if open
    if (this._sseController) {
      this._sseController.abort();
      this._sseController = null;
    }
    this.started = false;
  }
}
