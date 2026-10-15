// Local, read-only operations console. No client environment or auth values
// are returned. The server never runs configured tools or modifies policy.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { listGated, manifestStatus } from './fleet.js';
import { assertProxyManifest } from './manifest.js';

export function fleetSnapshot(configPath) {
  const { gated, ungated } = listGated(configPath);
  return {
    observedAt: new Date().toISOString(),
    source: configPath,
    servers: gated.map((g) => {
      try {
        const m = JSON.parse(readFileSync(g.manifest, 'utf8'));
        assertProxyManifest(m);
        return { name: g.name, manifest: g.manifest, ...manifestStatus(m), expiresAt: m.expiresAt,
          mode: g.flags.includes('--allow-all') ? 'audit bypass' : g.flags.includes('--auto-update') ? 'auto-update' : g.flags.includes('--strict') ? 'strict' : 'filter',
          provenance: 'local enforcement policy; publisher signature not verified',
          tools: m.tools.map((t) => ({ name: t.name, allowed: t.allowed, scopes: t.requiredScopes ?? [], override: !!t.manualOverride,
            reason: t.overrideReason ?? (t.allowed ? 'permitted by local policy' : 'denied by local policy'), contractDigest: t.contractDigest ?? null })) };
      } catch { return { name: g.name, state: 'invalid or missing manifest', tools: [] }; }
    }),
    ungated: ungated.map(({ name, transport }) => ({ name, transport })),
  };
}

const page = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Trustcard · Gates</title><link rel="stylesheet" href="/style.css"><body><header><div class="brand">◈ TRUSTCARD</div><span class="pill">LOCAL · READ ONLY</span></header><main><div class="eyebrow">TOOL ACCESS OPERATIONS</div><h1>Know where the gates are.</h1><p class="intro">Local policy, tool access and expiry in one place. Reloads every 10 seconds.</p><section id="stats"></section><div id="notice"></div><h2>Gated servers</h2><div id="servers"></div><h2>Connections outside this inventory's gates</h2><div id="ungated"></div><footer>Inventory reflects the selected JSON config. It does not establish runtime reachability, publisher authenticity or coverage of other clients. Change policy through reviewed CLI operations with backups; this console has no write API.</footer></main><script src="/app.js"></script></body></html>`;
const css = `:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0c111b;color:#e8edf5}body{margin:0}header{display:flex;align-items:center;justify-content:space-between;padding:24px 5vw;border-bottom:1px solid #263044}.brand{font-weight:750;letter-spacing:.16em}.pill,.eyebrow{font-size:11px;letter-spacing:.15em;color:#87dabd}.pill{padding:8px 12px;border:1px solid #36564f;border-radius:20px}main{max-width:1100px;margin:60px auto;padding:0 28px}h1{font-size:clamp(32px,5vw,56px);letter-spacing:-.05em;margin:12px 0}.intro,footer{color:#9daabc;line-height:1.65}#stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:36px 0}.stat{padding:24px;border:1px solid #29364a;background:#131c2a;border-radius:12px}.stat strong{display:block;font-size:32px}.stat span{font-size:13px;color:#9daabc}h2{font-size:17px;margin-top:38px}details{background:#131c2a;border:1px solid #29364a;border-radius:12px;margin:10px 0;overflow:hidden}summary{padding:22px;cursor:pointer;display:flex;gap:14px;flex-wrap:wrap;align-items:center}summary strong{margin-right:auto}.status{font-size:12px;border-radius:6px;padding:5px 8px;background:#26364a}.ok{color:#87dabd}.warn{color:#ffc477}.details{padding:0 22px 22px;color:#9daabc;font-size:13px;overflow:auto}table{width:100%;border-collapse:collapse;text-align:left;margin-top:18px}td,th{padding:12px 10px;border-bottom:1px solid #263044;vertical-align:top}td:first-child{color:#e8edf5;word-break:break-word}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#9daabc}.allowed{color:#87dabd}.denied{color:#ff9b9b}.connection{padding:15px 0;border-bottom:1px solid #263044;color:#9daabc}footer{font-size:12px;margin-top:42px}#notice{color:#ffc477;font-size:13px}@media(max-width:600px){#stats{gap:8px}.stat{padding:16px}main{margin-top:36px}}`;
const js = `const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n};
async function refresh(){try{const r=await fetch('/api/status');if(!r.ok)throw Error('Inventory unavailable');const d=await r.json();const stats=document.querySelector('#stats');stats.replaceChildren();for(const [n,label]of [[d.servers.length,'gated servers'],[d.servers.reduce((n,s)=>n+s.tools.length,0),'policy entries'],[d.ungated.length,'ungated connections']]){const x=el('div',undefined,'stat');x.append(el('strong',String(n)),el('span',label));stats.append(x)}const root=document.querySelector('#servers');const opened=new Set([...root.querySelectorAll('details[open]')].map(x=>x.dataset.server));root.replaceChildren();for(const s of d.servers){const box=el('details');box.dataset.server=s.name;box.open=opened.has(s.name);const sum=el('summary');sum.append(el('strong',s.name),el('span',s.mode||'unavailable','status'),el('span',s.state,'status '+(s.state==='ok'?'ok':'warn')),el('span',s.tools.length+' tools','status'));box.append(sum);const body=el('div',undefined,'details');body.append(el('p','Expiry: '+(s.expiresAt||'none')+' · '+(s.daysLeft??'?')+' days left'),el('p',s.provenance||'Policy could not be read'));const table=el('table');const head=el('tr');for(const h of ['Tool','Decision','Scopes','Reason'])head.append(el('th',h));table.append(head);for(const t of s.tools){const tr=el('tr');tr.append(el('td',t.name),el('td',t.allowed?'ALLOW':'DENY',t.allowed?'allowed':'denied'),el('td',t.scopes.join(', ')||'unscoped'),el('td',t.reason+(t.override?' · manual override':'')));table.append(tr)}body.append(table);box.append(body);root.append(box)}const un=document.querySelector('#ungated');un.replaceChildren();for(const u of d.ungated)un.append(el('div',u.name+' · '+u.transport,'connection'));if(!d.ungated.length)un.append(el('p','None in this config.'));document.querySelector('#notice').textContent='Observed '+new Date(d.observedAt).toLocaleString()+' · source: '+d.source;}catch(e){document.querySelector('#notice').textContent=e.message;}}
refresh();setInterval(refresh,10000);`;

export function startConsole({ configPath, port = 0 }) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('port must be an integer between 0 and 65535');
  fleetSnapshot(configPath); // Fail before opening a listener on invalid config.
  const server = createServer((req, res) => {
    const allowedHosts = new Set([`127.0.0.1:${server.address().port}`, `localhost:${server.address().port}`]);
    if (!allowedHosts.has(req.headers.host) || req.headers.origin && ![`http://127.0.0.1:${server.address().port}`, `http://localhost:${server.address().port}`].includes(req.headers.origin)) {
      res.writeHead(403); res.end(); return;
    }
    if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    const routes = { '/': ['text/html', page], '/style.css': ['text/css', css], '/app.js': ['text/javascript', js] };
    if (req.url === '/api/status') {
      try { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(fleetSnapshot(configPath))); }
      catch { res.writeHead(503); res.end(JSON.stringify({ error: 'inventory unavailable' })); }
    } else if (routes[req.url]) { const [type, content] = routes[req.url]; res.setHeader('Content-Type', type); res.end(content); }
    else { res.writeHead(404); res.end(); }
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}
