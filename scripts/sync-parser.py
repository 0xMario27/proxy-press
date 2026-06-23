#!/usr/bin/env python3
"""同步 sub-converter-parser.js + server.js → worker/worker.js"""
import re

# 1. 准备 parser
p = open('sub-converter-parser.js').read()
p = p.replace("'use strict';\n\n", "")
p = re.sub(r'\nmodule\.exports\s*=\s*\{[^}]+\};', '', p, flags=re.DOTALL)
p = p.replace("return Buffer.from(str, 'base64').toString('utf-8');", "return atob(str);")
p = p.replace("Buffer.from(str.replace(/\\s/g, ''), 'base64').toString('utf-8')", "atob(str.replace(/\\s/g, ''))")

# 2. 读取 server.js 的核心构建逻辑（去掉 Node.js 部分）
s = open('server.js').read()
# 提取从 "常量" 到 "启动" 之间的逻辑
s = s[s.find('// ═══════════════════════════════════  常量'):s.find('// ═══════════════════════════════════  HTTP 请求处理')]

# 3. 构建 Worker：parser + 适配后的 server 逻辑 + Worker 网络层
worker = f"""/**
 * ProxyPress Worker v6 — 与本地 server.js 完全一致
 * parser + config 构建逻辑全部同步
 */

// ═══════════════════════════════════════════════════════════
//  Parser（来自 sub-converter-parser.js，make sync 同步）
// ═══════════════════════════════════════════════════════════

{p}

// ═══════════════════════════════════════════════════════════
//  Config 构建逻辑（来自 server.js，与本地完全一致）
// ═══════════════════════════════════════════════════════════

const BASE_RULES_URL = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/';
const CONFIG_BASE = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/';

// 网络请求（替代 Node.js http/https）
async function fetchText(url, timeout = 30000) {{
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {{
    const r = await fetch(url, {{ headers: {{ 'User-Agent': 'sub-smart-js/1.0', 'Accept': '*/*' }}, signal: ctrl.signal }});
    if (r.status >= 400) throw new Error(`HTTP ${{r.status}}`);
    return await r.text();
  }} finally {{ clearTimeout(t); }}
}}

function isBase64(str) {{
  return /^[A-Za-z0-9+/=\\s\\r\\n]+$/.test(str.trim()) && str.length > 50 && !str.includes('<');
}}

function base64Decode(str) {{
  try {{ return atob(str.replace(/\\s/g, '')); }} catch {{ return str; }}
}}

// ─── .ini 配置解析 ───
function parseRulesets(iniContent) {{
  const rulesets = [];
  const re = /^ruleset\\s*=\\s*(.+?)\\s*,\\s*(.+)/gm;
  let m;
  while ((m = re.exec(iniContent)) !== null) rulesets.push({{ group: m[1].trim(), url: m[2].trim() }});
  return rulesets;
}}

function parseCustomProxyGroups(iniContent) {{
  const groups = [];
  const re = /^custom_proxy_group\\s*=\\s*(.+?)`(.+?)`(.*)/gm;
  let m;
  while ((m = re.exec(iniContent)) !== null) {{
    const name = m[1].trim(), type = m[2].trim(), rawRest = m[3].trim();
    const items = []; let filter = '';
    if (type === 'url-test' || type === 'fallback') {{
      const parts = rawRest.split('`');
      filter = parts[0] || '';
      items.push({{ filter }});
      for (let i = 1; i < parts.length; i += 3) items.push({{ url: parts[i] || '', interval: parts[i+1] || '300', tolerance: parts[i+2] || '50' }});
    }} else {{
      const itemRe = /\\[\\]([^`\\n]+)/g; let im;
      while ((im = itemRe.exec('[]' + rawRest)) !== null) items.push(im[1].trim());
    }}
    groups.push({{ name, type, items, filter, raw: rawRest }});
  }}
  return groups;
}}

// ─── 规则获取 ───
function processRuleText(text, group, rules) {{
  if (/^<[!]?DOCTYPE|^<html|<head|<body|Not Found|^[0-9]{{3}}:/.test(text.trim())) return;
  for (const line of text.split('\\n')) {{
    const s = line.trim();
    if (!s || s.startsWith('#') || s.startsWith(';')) continue;
    if (!/^(DOMAIN|IP-CIDR|GEOIP|MATCH|RULE-SET|DST-PORT|SRC-PORT|PROCESS-NAME)/i.test(s)) continue;
    const parts = s.split(','), last = parts[parts.length - 1].trim();
    if (last === 'no-resolve' || last === 'src' || last === 'dst' || !last) rules.push({{ group, line: s + ',' + group }});
    else if (parts.length >= 3) rules.push({{ group, line: s }});
    else rules.push({{ group, line: s + ',' + group }});
  }}
}}

async function fetchRulesFromConfig(rulesets) {{
  const rules = [], ps = [];
  for (const {{ group, url: ruleUrl }} of rulesets) {{
    const fullUrl = ruleUrl.startsWith('http') ? ruleUrl : (BASE_RULES_URL + ruleUrl.replace(/^Clash\\//, ''));
    ps.push(fetchText(fullUrl, 10000).then(t => processRuleText(t, group, rules)).catch(() => {{}}));
  }}
  await Promise.all(ps);
  rules.push({{ group: '🎯 全球直连', line: 'GEOIP,CN,🎯 全球直连' }});
  rules.push({{ group: '🐟 漏网之鱼', line: 'MATCH,🐟 漏网之鱼' }});
  return rules;
}}

// ─── 节点处理 ───
const REGION_MAP = [
  ['香港','🇭🇰'],['台湾','🇨🇳'],['日本','🇯🇵'],['美国','🇺🇸'],['韩国','🇰🇷'],['新加坡','🇸🇬'],
  ['英国','🇬🇧'],['德国','🇩🇪'],['印度','🇮🇳'],['越南','🇻🇳'],['泰国','🇹🇭'],['菲律宾','🇵🇭'],
  ['加拿大','🇨🇦'],['澳大利亚','🇦🇺'],['澳门','🇲🇴'],['马来西亚','🇲🇾'],['俄罗斯','🇷🇺'],
  ['土耳其','🇹🇷'],['印度尼西亚','🇮🇩'],['巴西','🇧🇷'],['阿根廷','🇦🇷'],['法国','🇫🇷'],['意大利','🇮🇹'],
];

function detectRegion(name) {{ for (const [kw, flag] of REGION_MAP) {{ if (name.includes(kw)) return {{ kw, flag }}; }} return null; }}

function enhanceNodes(nodes) {{
  for (const n of nodes) {{
    n.rawName = n.name;
    const r = detectRegion(n.name);
    if (r && !n.name.startsWith(r.flag)) n.name = r.flag + ' ' + n.name;
    n.region = r ? r.kw : null;
  }}
}}

// ─── 节点格式化 ───
function formatNodeCompact(n) {{
  const f = [];
  f.push(`name: ${{JSON.stringify(n.rawName)}}`);
  f.push(`type: ${{n.type}}`); f.push(`server: ${{n.server}}`); f.push(`port: ${{n.port}}`);
  const pwd = n.password || n.uuid || '';
  if (pwd) f.push(`password: ${{JSON.stringify(pwd)}}`);
  if (n.cipher && n.cipher !== 'auto') f.push(`cipher: ${{JSON.stringify(n.cipher)}}`);
  if (n.udp) f.push('udp: true');
  if (n['skip-cert-verify']) f.push('skip-cert-verify: true');
  const sn = n.sni || n.servername || '';
  if (sn && sn !== n.server) f.push(`servername: ${{JSON.stringify(sn)}}`);
  if (n.tls && n.tls !== 'none') {{ f.push('tls: true'); if (n.alpn && n.alpn.length) f.push(`alpn: [${{n.alpn}}]`); }}
  if (n.network && n.network !== 'tcp') {{
    f.push(`network: ${{n.network}}`);
    if (n.host) f.push(`host: ${{JSON.stringify(n.host)}}`);
    if (n.path && n.path !== '/') f.push(`path: ${{JSON.stringify(n.path)}}`);
  }}
  if (n.fingerprint && n.fingerprint !== 'chrome') f.push(`client-fingerprint: ${{JSON.stringify(n.fingerprint)}}`);
  return `  - {{${{f.join(', ')}}}}`;
}}

// ─── 配置构建（与 server.js 一致）───
const RULE_STORE = new Map();
function simpleHash(s) {{ let h=0; for(let i=0;i<s.length;i++){{ h=((h<<5)-h)+s.charCodeAt(i); h|=0; }} return Math.abs(h).toString(16).padStart(8,'0').slice(0,8); }}
function sanitize(s) {{ return s.replace(/[^\\w\\u4e00-\\u9fff]/g,'_').replace(/_+/g,'_').replace(/^_|_$/g,'')||'other'; }}
function quoteYaml(s) {{ return /[\\[\\]{{}}:,#&*?|><=!%@`\"']/.test(s) ? JSON.stringify(s) : s; }}

function buildRuleProviders(ruleData, host) {{
  if (!ruleData.length) return [];
  const rgs = {{}};
  for (const r of ruleData) {{ if (!rgs[r.group]) rgs[r.group] = []; rgs[r.group].push(r.line); }}
  const ls = ['rule-providers:'];
  for (const [g, ls2] of Object.entries(rgs)) {{
    const c = ls2.join('\\n'), h = simpleHash(c), n = sanitize(g);
    RULE_STORE.set(h, c);
    ls.push(`  ${{n}}: {{type: http, behavior: classical, path: ./rulesets/${{n}}.yaml, url: ${{host}}/rules/${{h}}.yaml, interval: 86400}}`);
  }}
  return ls;
}}

function buildRuleRefs(ruleData) {{
  if (!ruleData.length) return [];
  const seen = new Set(), refs = [];
  for (const r of ruleData) {{ const n = sanitize(r.group), k = `${{n}},${{r.group}}`; if (!seen.has(k)) {{ seen.add(k); refs.push(`  - RULE-SET,${{n}},${{r.group}}`); }} }}
  return refs;
}}

function buildProviderConfig(nodes, ruleData, host, rawSubUrl) {{
  const ls = ['port: 7890','socks-port: 7891','allow-lan: true','mode: Rule','log-level: info','',
    'proxy-providers:','  provider:','    type: http','    path: ./proxy-providers/provider.yaml',
    `    url: ${{host}}/list?url=${{encodeURIComponent(decodeURIComponent(rawSubUrl))}}`,
    '    interval: 86400','    health-check:','      enable: true','      url: http://www.gstatic.com/generate_204','      interval: 300',''];
  ls.push(...buildRuleProviders(ruleData, host));
  ls.push(...buildGroupsWithProvider(nodes));
  ls.push('', 'rules:', ...buildRuleRefs(ruleData));
  return ls.join('\\n');
}}

function buildInlineConfig(nodes, ruleData, host) {{
  const ls = ['port: 7890','socks-port: 7891','allow-lan: true','mode: Rule','log-level: info','','proxies:'];
  for (const n of nodes) ls.push(formatNodeCompact(n));
  ls.push('', ...buildRuleProviders(ruleData, host));
  ls.push(...buildGroupsInline(nodes));
  ls.push('', 'rules:', ...buildRuleRefs(ruleData));
  return ls.join('\\n');
}}

function buildGroupsWithProvider(nodes) {{
  const ls = ['proxy-groups:'], rs = new Map();
  for (const n of nodes) {{ if (n.region && !rs.has(n.region)) {{ const f = REGION_MAP.find(r=>r[0]===n.region)?.[1]||''; rs.set(n.region, f); }} }}
  ls.push('  - name: 🚀 节点选择','    type: select','    proxies:','      - ♻️ 自动选择');
  for (const [r,f] of rs) ls.push(`      - ${{f}} ${{r}}节点`);
  ls.push('      - 🚀 手动切换','      - DIRECT');
  ls.push('  - name: 🚀 手动切换','    type: select','    use:','      - provider','    proxies:','      - DIRECT');
  ls.push('  - name: ♻️ 自动选择','    type: url-test','    use:','      - provider','    url: http://www.gstatic.com/generate_204','    interval: 300','    tolerance: 50');
  for (const [r,f] of rs) ls.push(`  - name: ${{f}} ${{r}}节点`,'    type: url-test','    use:','      - provider',`    filter: "${{r}}"`,'    url: http://www.gstatic.com/generate_204','    interval: 300','    tolerance: 50');
  addTargetGroups(ls, rs);
  return ls;
}}

function buildGroupsInline(nodes) {{
  const ls = ['proxy-groups:'], rs = new Map();
  for (const n of nodes) {{ if (n.region && !rs.has(n.region)) {{ const f = REGION_MAP.find(r=>r[0]===n.region)?.[1]||''; rs.set(n.region, f); }} }}
  ls.push('  - name: 🚀 节点选择','    type: select','    proxies:','      - ♻️ 自动选择');
  for (const [r,f] of rs) ls.push(`      - ${{f}} ${{r}}节点`);
  ls.push('      - 🚀 手动切换','      - DIRECT');
  ls.push('  - name: 🚀 手动切换','    type: select','    proxies:');
  for (const n of nodes) ls.push(`      - ${{quoteYaml(n.rawName)}}`);
  ls.push('      - DIRECT');
  ls.push('  - name: ♻️ 自动选择','    type: url-test','    proxies:');
  for (const n of nodes) ls.push(`      - ${{quoteYaml(n.rawName)}}`);
  ls.push('    url: http://www.gstatic.com/generate_204','    interval: 300','    tolerance: 50');
  for (const [r,f] of rs) {{
    const rn = nodes.filter(n=>n.region===r);
    if (rn.length) {{ ls.push(`  - name: ${{f}} ${{r}}节点`,'    type: url-test','    proxies:'); for (const n of rn) ls.push(`      - ${{quoteYaml(n.rawName)}}`); ls.push('    url: http://www.gstatic.com/generate_204','    interval: 300','    tolerance: 50'); }}
  }}
  addTargetGroups(ls, rs);
  return ls;
}}

function addTargetGroups(ls, rs) {{
  const rgn = []; for (const [r,f] of rs) rgn.push(`${{f}} ${{r}}节点`);
  for (const t of ['🎯 全球直连','🛑 广告拦截','🍃 应用净化','🐟 漏网之鱼','📲 电报消息','📹 油管视频','🎥 奈飞视频','📺 哔哩哔哩','🌍 国外媒体','🌏 国内媒体','📢 谷歌FCM','Ⓜ️ 微软Bing','Ⓜ️ 微软云盘','Ⓜ️ 微软服务','🍎 苹果服务','🎶 网易音乐','💬 Ai平台','🎮 游戏平台']) {{
    if (t === '🎯 全球直连') ls.push(`  - name: ${{t}}`,'    type: select','    proxies:','      - DIRECT','      - 🚀 节点选择');
    else if (t === '🛑 广告拦截' || t === '🍃 应用净化') ls.push(`  - name: ${{t}}`,'    type: select','    proxies:','      - REJECT','      - DIRECT');
    else if (['🌏 国内媒体','📺 哔哩哔哩','🎶 网易音乐','Ⓜ️ 微软Bing','Ⓜ️ 微软云盘','Ⓜ️ 微软服务','🍎 苹果服务'].includes(t)) {{
      ls.push(`  - name: ${{t}}`,'    type: select','    proxies:','      - DIRECT','      - 🚀 节点选择','      - ♻️ 自动选择');
      for (const g of rgn) ls.push(`      - ${{g}}`);
    }} else {{
      ls.push(`  - name: ${{t}}`,'    type: select','    proxies:','      - 🚀 节点选择','      - ♻️ 自动选择');
      for (const g of rgn) ls.push(`      - ${{g}}`);
      ls.push('      - DIRECT');
    }}
  }}
}}

// ═══════════════════════════════════════════════════════════
//  Worker 入口
// ═══════════════════════════════════════════════════════════

export default {{
  async fetch(request) {{
    const u = new URL(request.url), p = u.pathname;
    if (p === '/health') return new Response('OK');
    if (p === '/version') return new Response('sub-smart-js v1.0');
    
    if (p === '/fetch') {{
      const fu = u.searchParams.get('url');
      if (!fu) return new Response('Missing url', {{ status: 400 }});
      return new Response(await fetchText(fu));
    }}
    
    if (p.startsWith('/rules/') && p.endsWith('.yaml')) {{
      const h = p.split('/rules/')[1].replace('.yaml','');
      const c = RULE_STORE.get(h);
      return c ? new Response(c, {{ headers: {{ 'Content-Type': 'text/plain','Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age=86400' }} }}) : new Response('Not found', {{ status: 404 }});
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
          if (!configFile.startsWith('http')) {{
            iniUrl = CONFIG_BASE + configFile.replace(/^.*\\//, '');
          }}
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

// ─── 订阅获取与解析 ───
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
print(f'✅ Worker v6 built ({len(worker)} chars)')
