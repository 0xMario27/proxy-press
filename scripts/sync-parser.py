#!/usr/bin/env python3
"""稳定同步：parser + shared → worker/worker.js"""
import re

# 1. Parser（来自 sub-converter-parser.js）
p = open('sub-converter-parser.js').read()
p = p.replace("'use strict';\n\n", "")
p = re.sub(r'\nmodule\.exports\s*=\s*\{[^}]+\};', '', p, flags=re.DOTALL)
p = p.replace("return Buffer.from(str, 'base64').toString('utf-8');", "return atob(str);")
p = p.replace("Buffer.from(str.replace(/\\s/g, ''), 'base64').toString('utf-8')", "atob(str.replace(/\\s/g, ''))")

# 2. Shared（来自 shared.js，由 server.js 独立维护）
s = open('shared.js').read()

# 3. Worker 网络层
worker = f"""/**
 * ProxyPress Worker v7 — 稳定同步（parser + shared.js）
 */

// ═══════════════════════════════════════════════════════════
//  Parser（来自 sub-converter-parser.js）
// ═══════════════════════════════════════════════════════════

{p}

// ═══════════════════════════════════════════════════════════
//  Shared logic（来自 shared.js，与 server.js 共用）
// ═══════════════════════════════════════════════════════════

const path = {{ join: (...args) => args.join('/'), basename: (s) => s.split('/').pop() }};
{s}

// ═══════════════════════════════════════════════════════════
//  Worker 入口
// ═══════════════════════════════════════════════════════════

const CONFIG_BASE = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/';

async function fetchText(url, timeout = 30000) {{
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {{
    const r = await fetch(url, {{ headers: {{ 'User-Agent': 'sub-smart-js/1.0', 'Accept': '*/*' }}, signal: ctrl.signal }});
    if (r.status >= 400) throw new Error(`HTTP ${{r.status}}`);
    return await r.text();
  }} finally {{ clearTimeout(t); }}
}}

export default {{
  async fetch(request) {{
    const u = new URL(request.url), p = u.pathname;
    if (p === '/health') return new Response('OK');
    if (p === '/version') return new Response('sub-smart-js v1.0');

    if (p === '/fetch') {{
      const fu = u.searchParams.get('url');
      return fu ? new Response(await fetchText(fu)) : new Response('Missing url', {{ status: 400 }});
    }}

    if (p.startsWith('/rules/') && p.endsWith('.yaml')) {{
      const h = p.split('/rules/')[1].replace('.yaml','');
      const c = RULE_STORE.get(h);
      return c ? new Response(c, {{ headers: {{ 'Content-Type':'text/plain','Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age=86400' }} }}) : new Response('Not found', {{ status: 404 }});
    }}

    if (p === '/list') {{
      const lu = u.searchParams.get('url');
      if (!lu) return new Response('Missing url', {{ status: 400 }});
      const nodes = await fetchAndParseSub(lu);
      enhanceNodes(nodes);
      const y = ['proxies:']; for (const n of nodes) y.push(formatNodeCompact(n));
      return new Response(y.join('\\n'), {{ headers: {{ 'Content-Type':'text/plain','Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age=300' }} }});
    }}

    if (p === '/sub') {{
      const subUrl = u.searchParams.get('url');
      if (!subUrl) return new Response('Missing url', {{ status: 400 }});
      const mode = u.searchParams.get('mode') || 'provider';
      const configFile = u.searchParams.get('config') || '';

      try {{
        const nodes = await fetchAndParseSub(subUrl);
        if (!nodes.length) return new Response('No nodes found', {{ status: 400 }});
        enhanceNodes(nodes);

        let ruleData = [];
        if (configFile) {{
          let iniUrl = configFile;
          if (!configFile.startsWith('http'))
            iniUrl = CONFIG_BASE + configFile.replace(/^.*\\//, '');
          try {{
            const iniContent = await fetchText(iniUrl, 15000);
            if (iniContent) {{
              const rulesets = parseRulesets(iniContent);
              if (rulesets.length) ruleData = await fetchRulesFromConfig(rulesets);
            }}
          }} catch(e) {{}}
        }}

        const host = u.origin;
        const r = mode === 'provider' ? buildProviderConfig(nodes, ruleData, host, subUrl) : buildInlineConfig(nodes, ruleData, host);
        return new Response(r, {{ headers: {{ 'Content-Type':'text/plain; charset=utf-8','Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age=300' }} }});
      }} catch(e) {{ return new Response('Error: ' + e.message, {{ status: 502 }}); }}
    }}

    return new Response('ProxyPress v7', {{ status: 404 }});
  }}
}};

async function fetchAndParseSub(subUrl) {{
  if (!/^https?:\\/\\//.test(subUrl)) {{
    let body = decodeURIComponent(subUrl);
    if (isBase64(body) && !body.includes('://')) {{ const d = base64Decode(body); if (d.includes('://') || d.includes(' = ')) body = d; }}
    return parseSubscription(body);
  }}
  let body = await fetchText(subUrl);
  if (isBase64(body) && !body.includes('://')) {{ const d = base64Decode(body); if (d.includes('://')) body = d; }}
  return parseSubscription(body);
}}
"""

open('worker/worker.js', 'w').write(worker)
open('worker/parser.js', 'w').write(p)
print(f'✅ Synced ({len(worker)} chars)')
