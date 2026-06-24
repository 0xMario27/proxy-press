#!/usr/bin/env python3
"""sync-worker.py — parser.js + shared.js + formats.js → worker/worker.js"""

import re

parser = open('backend/parser.js').read()
shared = open('backend/shared.js').read()
formats = open('backend/formats.js').read()

# ─── parser: strip use strict / module.exports ───
parser = parser.replace("'use strict';\n\n", "")
parser = re.sub(r'\nmodule\.exports\s*=\s*\{[^}]+\};', '', parser, flags=re.DOTALL)

# ─── shared: strip use strict / module.exports / requires ───
shared = shared.replace("'use strict';\n\n", "")
shared = re.sub(r'\nmodule\.exports\s*=\s*\{[\s\S]*?\};', '', shared)
shared = re.sub(r"const path = require\('path'\).*\n", '', shared)
shared = re.sub(r"const fs = require\('fs'\).*\n", '', shared)
shared = re.sub(r"const CONFIG_DIR = .*;\n", '', shared)
shared = re.sub(r"const PORT = .*;\n", '', shared)
shared = re.sub(r"const HOST_IP = .*;\n", '', shared)
shared = shared.replace("__dirname", "''")

# shared.js worker compat transforms
shared = re.sub(
    r'function resolveLocalRule\(ruleUrl\) \{[\s\S]*?^\}',
    'function resolveLocalRule(ruleUrl) { return null; } /* Worker */',
    shared, flags=re.MULTILINE
)
shared = re.sub(
    r'async function fetchRulesFromConfig\(rulesets\) \{[\s\S]*?^\}',
    '''async function fetchRulesFromConfig(rulesets) {
  const rules = [];
  const promises = [];
  for (const { group, url: ruleUrl } of rulesets) {
    const fullUrl = ruleUrl.startsWith('http') ? ruleUrl : (BASE_RULES_URL + ruleUrl.replace(/^Clash\\//, ''));
    promises.push(fetchText(fullUrl, 10000).then(text => { processRuleText(text, group, rules); }).catch(() => {}));
  }
  await Promise.all(promises);
  rules.push({ group: '🎯 全球直连', line: 'GEOIP,CN,🎯 全球直连' });
  rules.push({ group: '🐟 漏网之鱼', line: 'MATCH,🐟 漏网之鱼' });
  return rules;
}''',
    shared, flags=re.DOTALL
)

# ─── formats: strip module.exports ───
formats = formats.replace("'use strict';\n\n", "")
formats = re.sub(r'\nmodule\.exports\s*=\s*\{[^}]+\};', '', formats, flags=re.DOTALL)

# ─── generic workerify ───
def workerify(code):
    code = code.replace("return Buffer.from(str, 'base64').toString('utf-8');", "return atob(str);")
    code = code.replace("try { return Buffer.from(str.replace(/\\s/g, ''), 'base64').toString('utf-8'); }", "try { return atob(str.replace(/\\s/g, '')); }")
    code = re.sub(r'^\s*console\.(?:log|error)\([^)]*\);?\n', '', code, flags=re.MULTILINE)
    code = re.sub(r"\bfs\.\w+\([^)]*\);?", '/* fs */', code)
    return code

shared = workerify(shared)

# ─── assemble worker ───
worker = f"""/**
 * ProxyPress Worker — auto-generated (make sync)
 */

// ═══ Parser (backend/parser.js) ═══

{parser}

// ═══ Shared logic (backend/shared.js, worker compat) ═══

const path = {{ join: (...args) => args.join('/'), basename: (s) => s.split('/').pop() }};

{shared}

// ═══ Formats (backend/formats.js) ═══

{formats}

// ═══ Worker platform ═══

const CONFIG_BASE = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/';

async function fetchText(url, timeout = 30000) {{
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {{
    const r = await fetch(url, {{ headers: {{ 'User-Agent':'sub-smart-js/1.0','Accept':'*/*' }}, signal: ctrl.signal }});
    if (r.status >= 400) throw new Error('HTTP ' + r.status);
    return await r.text();
  }} finally {{ clearTimeout(t); }}
}}

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

// ═══ Entry ═══

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
      return c ? new Response(c, {{ headers: {{ 'Content-Type':'text/plain','Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age=86400' }} }})
               : new Response('Not found', {{ status: 404 }});
    }}

    if (p === '/list') {{
      const lu = u.searchParams.get('url');
      if (!lu) return new Response('Missing url', {{ status: 400 }});
      const nodes = await fetchAndParseSub(lu);
      enhanceNodes(nodes);
      // 根据 target 参数选择格式
      const tgt = u.searchParams.get('target') || 'clash';
      if (tgt === 'surge' || tgt === 'surfboard') {{
        const y = []; for (const n of nodes) y.push(formatNodeSurge(n));
        return new Response(y.join('\\n'), {{ headers: {{ 'Content-Type':'text/plain','Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age=300' }} }});
      }}
      const y = ['proxies:']; for (const n of nodes) y.push(formatNodeCompact(n));
      return new Response(y.join('\\n'), {{ headers: {{ 'Content-Type':'text/plain','Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age=300' }} }});
    }}

    if (p === '/sub') {{
      const subUrl = u.searchParams.get('url');
      if (!subUrl) return new Response('Missing url', {{ status: 400 }});
      const mode = u.searchParams.get('mode') || 'provider';
      const target = u.searchParams.get('target') || 'clash';
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

        // 非 Clash 目标
        const altConfig = buildConfigForTarget(target, nodes, ruleData, host, subUrl);
        if (altConfig) return new Response(altConfig, {{ headers: {{ 'Content-Type':'text/plain; charset=utf-8','Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age=300' }} }});

        // Clash 系
        const r = mode === 'provider' ? buildProviderConfig(nodes, ruleData, host, subUrl) : buildInlineConfig(nodes, ruleData, host);
        return new Response(r, {{ headers: {{ 'Content-Type':'text/plain; charset=utf-8','Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age=300' }} }});
      }} catch(e) {{ return new Response('Error: ' + e.message, {{ status: 502 }}); }}
    }}

    return new Response('ProxyPress', {{ status: 404 }});
  }}
}};
"""

open('worker/worker.js', 'w').write(worker)
print(f'✅ sync-worker: worker/worker.js ({len(worker)} chars)')
