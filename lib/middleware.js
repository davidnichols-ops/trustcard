// Middleware: wrap ANY MCP client object ({ request, notify }) with trustcard
// enforcement — no fork required. This is how trustcard slots into existing
// agent frameworks as a standard middleware layer.
//
//   const secure = wrapClient(rawClient, { guard, session });
//   await secure.request("tools/call", { name, arguments });  // gated + receipted
//
// The wrapper intercepts:
//   - tools/call     → guard authorization + receipt
//   - tools/list     → digest re-verification against the session's pin
//                        (cheap TOCTOU check on every enumeration)
import { toolsetDigest } from "./identity.js";

export function wrapClient(client, { guard, session, strictArgs = false } = {}) {
  return {
    ...client,
    async request(method, params, ...rest) {
      if (method === "tools/call" && guard) {
        await guard.authorizeCall({
          session,
          tool: params?.name,
          args: params?.arguments ?? {},
          strict: strictArgs,
        });
        const result = await client.request(method, params, ...rest);
        guard.recordReceipt({ session, tool: params?.name, args: params?.arguments ?? {}, result });
        return result;
      }
      if (method === "tools/list" && session) {
        const result = await client.request(method, params, ...rest);
        const tools = Array.isArray(result?.tools) ? result.tools : [];
        const digest = toolsetDigest(tools);
        if (session.observation && digest !== session.observation.toolsetDigest) {
          // The toolset changed under us without (or before) a list_changed
          // notification — force the full refresh path.
          await session.refresh("list-digest-mismatch");
        }
        return result;
      }
      return client.request(method, params, ...rest);
    },
    notify: client.notify?.bind(client),
  };
}
