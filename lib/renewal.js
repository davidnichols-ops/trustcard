// Conservative background maintenance: no reapproval, no policy broadening.
import { listGated, renewServer } from './fleet.js';
import { redact } from './redact.js';
export async function renewalPass(configPath, { within = 14, days = 90, list } = {}) {
  if (!Number.isFinite(within) || within < 0 || !Number.isFinite(days) || days <= 0) throw new Error('invalid renewal duration');
  const { gated } = listGated(configPath);
  const results = [];
  for (const target of gated) {
    try { results.push(await renewServer(target, { onlyIfWithinDays: within, days, ...(list ? { list } : {}) })); }
    catch (e) { results.push({ name: target.name, ok: false, action: 'error', reason: redact(e.message) }); }
  }
  return { observedAt: new Date().toISOString(), ok: results.every((r) => r.ok), results };
}
export async function watchFleet(configPath, { intervalSeconds = 21_600, within = 14, days = 90, once = false } = {}) {
  if (!Number.isFinite(intervalSeconds) || intervalSeconds < 60) throw new Error('renewal interval must be at least 60 seconds');
  if (!Number.isFinite(within) || within < 0 || !Number.isFinite(days) || days <= 0) throw new Error('invalid renewal duration');
  let stopped = false, wake;
  const stop = () => { stopped = true; wake?.(); };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  try {
    do {
      try { const result = await renewalPass(configPath, { within, days }); process.stdout.write(JSON.stringify(result)+'\n'); if (once && !result.ok) process.exitCode = 1; }
      catch (e) { process.stdout.write(JSON.stringify({ observedAt: new Date().toISOString(), ok: false, error: redact(e.message) })+'\n'); if (once) process.exitCode = 1; }
      if (once || stopped) break;
      await new Promise((resolve) => { const timer = setTimeout(resolve, intervalSeconds*1000); wake = () => { clearTimeout(timer); resolve(); }; });
      wake = undefined;
    } while (!stopped);
  } finally { process.off('SIGTERM', stop); process.off('SIGINT', stop); }
}
