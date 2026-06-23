#!/usr/bin/env python3
"""同步 sub-converter-parser.js + server.js → worker/worker.js"""
import re

# 1. Parser
parser = open('sub-converter-parser.js').read()
parser = parser.replace("'use strict';\n\n", "")
parser = re.sub(r'\nmodule\.exports\s*=\s*\{[^}]+\};', '', parser, flags=re.DOTALL)
parser = parser.replace("return Buffer.from(str, 'base64').toString('utf-8');", "return atob(str);")
parser = parser.replace("Buffer.from(str.replace(/\\s/g, ''), 'base64').toString('utf-8')", "atob(str.replace(/\\s/g, ''))")

# 2. Server.js 核心逻辑（常量 → HTTP 请求处理 之前）
server = open('server.js').read()
# 找起始: "常量" 注释块
start = server.find('常量')
start = server.rfind('// ═', 0, start) if '常量' in server else server.find('REGION_MAP')
# 找结束: "订阅获取与解析" 注释块（fetchAndParseSub 由 Worker 网络层提供）
end = server.find('订阅获取与解析')
end = server.rfind('// ═', 0, end) if '订阅获取与解析' in server else server.find('HTTP 请求处理')
server_core = server[start:end].strip()
# 移除 Node.js 特定的 fetchText（Worker 网络层有自己的 fetch-based 版本）
server_core = re.sub(r'function fetchText\([^)]*\).*?^\}', '', server_core, flags=re.MULTILINE | re.DOTALL)
server_core = server_core.replace('__dirname', '""')
server_core = re.sub(r'fs\.existsSync\([^)]+\)', 'false', server_core)
server_core = re.sub(r'fs\.readFileSync\([^)]+\)', '""', server_core)
server_core = server_core.replace('process.env.PORT', '25600')
server_core = server_core.replace('process.env.HOST_IP', '"localhost"')
# 添加 path polyfill 到 worker
path_polyfill = "const path = { join: (...args) => args.join('/'), basename: (s) => s.split('/').pop() };"

# 3. 构建 Worker（无重复函数）
worker = f"""/**
 * ProxyPress Worker v6 — 与本地 server.js 完全一致
 * make sync 自动同步 parser + config 构建逻辑
 */

// ═══════════════════════════════════════════════════════════
//  Parser（来自 sub-converter-parser.js）
// ═══════════════════════════════════════════════════════════

{parser}

// ═══════════════════════════════════════════════════════════
//  Config 构建逻辑（来自 server.js，与本地完全一致）
// ═══════════════════════════════════════════════════════════

// Worker polyfills（Node.js API → 浏览器兼容）
{path_polyfill}

{server_core}

// ═══════════════════════════════════════════════════════════
//  Worker 入口
// ═══════════════════════════════════════════════════════════

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
      const y = ['proxies:'];
      for (const n of nodes) y.push(formatNodeCompact(n));
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

    return new Response('ProxyPress v6', {{ status: 404 }});
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
open('worker/parser.js', 'w').write(parser)
print(f'✅ Synced ({len(worker)} chars)')
