#!/usr/bin/env python3
"""稳定同步：parser + shared → worker/worker.js

对 shared.js 做 Worker 兼容转换：
  - Buffer.from → atob()
  - 替换 resolveLocalRule（Worker 无本地文件）
  - 替换 fetchRulesFromConfig（移除 fs 调用）
  - __dirname → ''
  - process.env → 默认值
"""
import re

# 1. Parser（来自 backend/parser.js）
p = open('backend/parser.js').read()
p = p.replace("'use strict';\n\n", "")
p = re.sub(r'\nmodule\.exports\s*=\s*\{[^}]+\};', '', p, flags=re.DOTALL)
p = p.replace("return Buffer.from(str, 'base64').toString('utf-8');", "return atob(str);")
p = p.replace("Buffer.from(str.replace(/\\s/g, ''), 'base64').toString('utf-8')", "atob(str.replace(/\\s/g, ''))")

# 2. Shared（来自 backend/shared.js，做 Worker 兼容转换）
s = open('backend/shared.js').read()

# 2a. Buffer → atob
s = s.replace("return Buffer.from(str.replace(/\\s/g, ''), 'base64').toString('utf-8');", "return atob(str.replace(/\\s/g, ''));")

# 2b. 移除不需要的常量
s = re.sub(r'const CONFIG_DIR = .*\n', '', s)
s = re.sub(r'const PORT = .*\n', '', s)
s = re.sub(r'const HOST_IP = .*\n', '', s)

# 2c. __dirname → ''
s = s.replace('__dirname', "''")

# 2d. 替换 resolveLocalRule 为 Worker 安全版
OLD_RESOLVE = r'function resolveLocalRule\(ruleUrl\) \{.*?\n\}'
NEW_RESOLVE = 'function resolveLocalRule(ruleUrl) { return null; } /* Worker: no local fs */'
s = re.sub(OLD_RESOLVE, NEW_RESOLVE, s, flags=re.DOTALL)

# 2e. 替换 fetchRulesFromConfig 为 Worker 安全版（纯远程获取）
OLD_FETCH_RULES = r'async function fetchRulesFromConfig\(rulesets\) \{.*?\n\}'
NEW_FETCH_RULES = '''async function fetchRulesFromConfig(rulesets) {
  const rules = [];
  const promises = [];
  for (const { group, url: ruleUrl } of rulesets) {
    const fullUrl = ruleUrl.startsWith('http') ? ruleUrl : (BASE_RULES_URL + ruleUrl.replace(/^Clash\\//, ''));
    promises.push(
      fetchText(fullUrl, 10000).then(text => {
        processRuleText(text, group, rules);
      }).catch(() => {})
    );
  }
  await Promise.all(promises);
  rules.push({ group: '🎯 全球直连', line: 'GEOIP,CN,🎯 全球直连' });
  rules.push({ group: '🐟 漏网之鱼', line: 'MATCH,🐟 漏网之鱼' });
  return rules;
}'''
s = re.sub(OLD_FETCH_RULES, NEW_FETCH_RULES, s, flags=re.DOTALL)

# 2f. 移除残留的 fs 引用（防御性）
s = re.sub(r'\bfs\.\w+\([^)]*\);?', '/* fs removed */', s)

# 3. Worker 网络层
worker = f"""/**
 * ProxyPress Worker v8 — 稳定同步（parser + shared.js）
 */

// ═══════════════════════════════════════════════════════════
//  Parser（来自 backend/parser.js）
// ═══════════════════════════════════════════════════════════

{p}

// ═══════════════════════════════════════════════════════════
//  Shared logic（来自 backend/shared.js，Worker 兼容转换）
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

    return new Response('ProxyPress v8', {{ status: 404 }});
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
