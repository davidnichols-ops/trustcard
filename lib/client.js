// Minimal JSON-RPC 2.0 client over stdio for probing MCP servers.
// No dependencies — speaks newline-delimited JSON-RPC to a child process.
import { spawn } from "node:child_process";

// Minimal environment for spawned (untrusted) servers: enough for node,
// npm/npx, and typical MCP servers to run — without leaking the operator's
// shell secrets (cloud credentials, API tokens, agent sockets, signing keys)
// to the process under audit. Variables NOT on this list are withheld unless
// the caller explicitly supplies them via `env`.
export const CHILD_ENV_ALLOWLIST = [
  // execution basics — PATH and a home directory are required by npm/npx
  // (cache at ~/.npm) and by virtually every child process
  "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TEMP", "TMP",
  // locale / terminal / timezone — behavior-neutral but commonly required
  "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TERM", "COLORTERM", "TZ",
  // XDG dirs some servers consult for config/cache locations
  "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR",
  // egress proxy settings — npm/npx cannot reach a registry without these on
  // proxied networks
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
  "http_proxy", "https_proxy", "all_proxy", "no_proxy",
  // Windows essentials — spawned processes fail without SystemRoot/PATHEXT
  "SystemRoot", "SYSTEMROOT", "COMSPEC", "PATHEXT", "APPDATA", "LOCALAPPDATA",
  "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "ProgramData", "WINDIR", "OS",
];

// Build the environment for a spawned server. With inheritEnv=false (the
// default) the child receives only allowlisted parent vars plus the caller's
// explicit `env`. With inheritEnv=true the full parent environment is
// inherited — kept for callers that legitimately need it (e.g. a sandbox
// runtime that has already constructed a complete env).
export function buildChildEnv(env = {}, { inheritEnv = false } = {}) {
  const base = {};
  if (inheritEnv) {
    Object.assign(base, process.env);
  } else {
    for (const key of CHILD_ENV_ALLOWLIST) {
      if (process.env[key] !== undefined) base[key] = process.env[key];
    }
  }
  for (const [k, v] of Object.entries(env ?? {})) base[k] = v;
  if (base.PATH == null) base.PATH = process.env.PATH ?? "";
  return base;
}

export class McpStdioClient {
  constructor({ cmd, args = [], env = {}, spawnTimeout = 60_000, cwd, detached = false, inheritEnv = false } = {}) {
    this.cmd = cmd;
    this.args = args;
    this.env = env;
    this.spawnTimeout = spawnTimeout;
    this.cwd = cwd;
    this.detached = detached;
    this.inheritEnv = inheritEnv;
    this.proc = null;
    this.buffer = "";
    this.pending = new Map();
    this.nextId = 1;
    this.stderr = "";
    this.started = false;
    this.listeners = new Map(); // notification method -> Set<fn>
  }

  // Subscribe to a server notification (e.g. "notifications/tools/list_changed").
  on(method, fn) {
    if (!this.listeners.has(method)) this.listeners.set(method, new Set());
    this.listeners.get(method).add(fn);
    return () => this.listeners.get(method)?.delete(fn);
  }

  async start() {
    return new Promise((resolve, reject) => {
      const proc = spawn(this.cmd, this.args, {
        env: buildChildEnv(this.env, { inheritEnv: this.inheritEnv }),
        stdio: ["pipe", "pipe", "pipe"],
        cwd: this.cwd,
        detached: this.detached,
      });
      this.proc = proc;
      const onTimeout = () => {
        if (!this.started) reject(new Error(`spawn timeout after ${this.spawnTimeout}ms`));
      };
      const timer = setTimeout(onTimeout, this.spawnTimeout);
      proc.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
      proc.on("exit", (code, signal) => {
        this.exitCode = code;
        this.exitSignal = signal;
        if (!this.started) {
          clearTimeout(timer);
          reject(new Error(`process exited before handshake (code=${code} signal=${signal})`));
        }
      });
      proc.stderr.on("data", (d) => {
        this.stderr += d.toString();
        if (this.stderr.length > 16_000) this.stderr = this.stderr.slice(-16_000);
      });
      proc.stdout.on("data", (d) => {
        this.buffer += d.toString();
        let idx;
        while ((idx = this.buffer.indexOf("\n")) >= 0) {
          const line = this.buffer.slice(0, idx).trim();
          this.buffer = this.buffer.slice(idx + 1);
          if (line) this._handle(line);
        }
      });
      // give the process a moment to be ready; resolve once stdout pipe is open
      this.started = true;
      clearTimeout(timer);
      resolve();
    });
  }

  _handle(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    if (msg.id != null && this.pending.has(msg.id)) {
      const { resolve, reject } = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      if (msg.error) reject(msg.error);
      else resolve(msg.result);
      return;
    }
    // Notification (no id): dispatch to subscribers.
    if (msg.method && this.listeners.has(msg.method)) {
      for (const fn of this.listeners.get(msg.method)) {
        try { fn(msg.params); } catch {}
      }
    }
  }

  request(method, params, timeoutMs = 15_000) {
    const id = this.nextId++;
    const body = { jsonrpc: "2.0", id, method, params: params ?? {} };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout: ${method} (${timeoutMs}ms)`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (r) => { clearTimeout(timer); resolve(r); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
      this.proc.stdin.write(JSON.stringify(body) + "\n");
    });
  }

  notify(method, params) {
    const body = { jsonrpc: "2.0", method, params: params ?? {} };
    this.proc.stdin.write(JSON.stringify(body) + "\n");
  }

  async stop() {
    if (!this.proc) return;
    try { this.proc.stdin.end(); } catch {}
    // When detached, the child is its own process group leader; kill the whole
    // group for best-effort process-tree cleanup. Otherwise kill the main process.
    if (this.detached) {
      try { process.kill(-this.proc.pid, "SIGTERM"); } catch {}
    } else {
      try { this.proc.kill("SIGTERM"); } catch {}
    }
    await new Promise((r) => setTimeout(r, 50));
    if (this.detached) {
      try { process.kill(-this.proc.pid, "SIGKILL"); } catch {}
    } else {
      try { this.proc.kill("SIGKILL"); } catch {}
    }
  }
}

export const PROTOCOL_VERSIONS = ["2025-06-18", "2024-11-05", "2024-10-07"];
