#!/usr/bin/env python3
"""sync-worker.py — 从 backend/{parser,shared,server}.js 生成 worker/worker.js

读取 parser.js + shared.js（业务逻辑）+ server.js（HTTP 层模式），
做 Worker 兼容转换后输出单文件。
"""
import re

# ═══════════════════════════════════════════════════════════
#  0. 工具函数
# ═══════════════════════════════════════════════════════════

def workerify(code):
    """Buffer → atob, 清除 module.exports / use strict / console"""
    # Buffer.from(X, 'base64').toString('utf-8') → atob(X)
    code = re.sub(
        r"Buffer\.from\((.+?),\s*'base64'\)\.toString\('utf-8'\)",
        r"atob(\1)", code
    )
    code = re.sub(r'\nmodule\.exports\s*=\s*\{[^}]+\};', '', code, flags=re.DOTALL)
    code = re.sub(r"^'use strict';\n\n", '', code)
    code = re.sub(r'^\s*console\.(?:log|error)\([^)]*\);?\n', '', code, flags=re.MULTILINE)
    return code


# ═══════════════════════════════════════════════════════════
#  1. 读取源文件
# ═══════════════════════════════════════════════════════════

parser = open('backend/parser.js').read()
shared = open('backend/shared.js').read()

# ═══════════════════════════════════════════════════════════
#  2. parser.js: 去 boilerplate + Buffer→atob
# ═══════════════════════════════════════════════════════════
parser = parser.replace("'use strict';\n\n", "")
parser = re.sub(r'\nmodule\.exports\s*=\s*\{[^}]+\};', '', parser, flags=re.DOTALL)
parser = workerify(parser)

# ═══════════════════════════════════════════════════════════
#  3. shared.js: Worker 兼容转换
# ═══════════════════════════════════════════════════════════

# 去掉 module.exports
shared = re.sub(r'\nmodule\.exports\s*=\s*\{[\s\S]*?\};', '', shared)

# 去掉平台常量
shared = re.sub(r"const CONFIG_DIR = .*;\n", '', shared)
shared = re.sub(r"const PORT = .*;\n", '', shared)
shared = re.sub(r"const HOST_IP = .*;\n", '', shared)
shared = re.sub(r"const path = require\('path'\);.*\n", '', shared)
shared = re.sub(r"const fs = require\('fs'\);.*\n", '', shared)

# __dirname → ''
shared = shared.replace("__dirname", "''")

# resolveLocalRule → Worker 安全版
shared = re.sub(
    r'function resolveLocalRule\(ruleUrl\) \{[\s\S]*?^\}',
    'function resolveLocalRule(ruleUrl) { return null; } /* Worker: no local fs */',
    shared, flags=re.MULTILINE
)

# fetchRulesFromConfig → 纯远程版
shared = re.sub(
    r'async function fetchRulesFromConfig\(rulesets\) \{[\s\S]*?^\}',
    '''async function fetchRulesFromConfig(rulesets) {
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
}''',
    shared, flags=re.DOTALL
)

# Buffer → atob（shared.js 中 base64Decode 也有 Buffer）
shared = workerify(shared)

# ═══════════════════════════════════════════════════════════
#  4. 组装 Worker
# ═══════════════════════════════════════════════════════════

worker = f"""/**
 * ProxyPress Worker — 自动生成自 backend/{{parser,shared}}.js
 * 生成命令: make sync
 */

// ═══════════════════════════════════════════════════════════
//  Parser（backend/parser.js）
// ═══════════════════════════════════════════════════════════

{parser}

// ═══════════════════════════════════════════════════════════
//  Business logic（backend/shared.js，Worker 兼容转换）
// ═══════════════════════════════════════════════════════════

const path = {{ join: (...args) => args.join('/'), basename: (s) => s.split('/').pop() }};

{shared}

// ═══════════════════════════════════════════════════════════
//  Worker 平台适配
// ═══════════════════════════════════════════════════════════

const CONFIG_BASE = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/';

async function fetchText(url, timeout = 30000) {{
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {{
    const r = await fetch(url, {{ headers: {{ 'User-Agent': 'sub-smart-js/1.0', 'Accept': '*/*' }}, signal: ctrl.signal }});
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

// ═══════════════════════════════════════════════════════════
//  HTTP 入口（对标 backend/server.js 的 handleRequest）
// ═══════════════════════════════════════════════════════════

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

    return new Response('ProxyPress', {{ status: 404 }});
  }}
}};
"""

open('worker/worker.js', 'w').write(worker)
print(f'✅ sync-worker: worker/worker.js ({len(worker)} chars)')
