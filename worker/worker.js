/**
 * ProxyPress Worker v4 — 纯 JS subconverter
 * 完全替代 subconverter C++ 镜像，本地和线上行为一致
 */

// ═══════════════════════════════════════════
//  节点解析器
// ═══════════════════════════════════════════

function parseNode(uri) {
  uri = uri.trim();
  if (!uri || uri.startsWith('#')) return null;

  // 尝试多种协议
  const parsed =
    tryParseSSR(uri) || tryParseSS(uri) ||
    tryParseVMess(uri) || tryParseVLess(uri) ||
    tryParseTrojan(uri) || tryParseHysteria(uri) ||
    tryParseAnyTLS(uri) || tryParseTUIC(uri);
  return parsed;
}

function tryParseSSR(uri) {
  // ssr://base64
  if (!uri.startsWith('ssr://')) return null;
  try {
    const b64 = uri.slice(6);
    const decoded = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    const parts = decoded.split(':');
    if (parts.length < 6) return null;
    const [server, port, proto, method, obfs, pwdB64] = parts;
    const password = atob(pwdB64.replace(/-/g, '+').replace(/_/g, '/'));
    const params = {};
    if (parts[6]) {
      const obfsParam = atob(parts[6].replace(/-/g, '+').replace(/_/g, '/'));
      const pairs = obfsParam.split('&');
      for (const p of pairs) {
        const [k, v] = p.split('=');
        if (k && v) params[k] = decodeURIComponent(v);
      }
      if (params.remarks) {
        return buildNode('ssr', server, parseInt(port), { password, ssr_protocol: proto, ssr_method: method, ssr_obfs: obfs, remarks: params.remarks, ...params });
      }
    }
  } catch (_) {}
  return null;
}

function tryParseSS(uri) {
  // ss://base64 or ss://method:password@server:port
  if (!uri.startsWith('ss://')) return null;
  try {
    let rest = uri.slice(5);
    // Handle SIP002 format: ss://method:password@server:port
    if (rest.includes('@')) {
      const m = rest.match(/^(.+):(.+)@(.+):(\d+)(?:\?([^#]*))?(?:#(.+))?$/);
      if (!m) return null;
      const [, method, password, server, port, query, name] = m;
      const params = parseQuery(query);
      return buildNode('ss', server, parseInt(port), { password, cipher: method, name: name || params.remarks, ...params });
    }
    // Legacy base64 format
    const decoded = atob(rest.replace(/-/g, '+').replace(/_/g, '/'));
    const m = decoded.match(/^(.+):(.+)@(.+):(\d+)$/);
    if (!m) return null;
    return buildNode('ss', m[3], parseInt(m[4]), { password: m[2], cipher: m[1] });
  } catch (_) {}
  return null;
}

function tryParseVMess(uri) {
  // vmess://base64json
  if (!uri.startsWith('vmess://')) return null;
  try {
    const b64 = uri.slice(8);
    const json = JSON.parse(atob(b64.replace(/-/g, '+').replace(/_/g, '/')));
    return buildNode('vmess', json.add, parseInt(json.port), {
      password: json.id, alterId: json.aid, cipher: json.scy || 'auto',
      network: json.net, wsPath: json.path, wsHeaders: json.host ? { Host: json.host } : undefined,
      tls: json.tls === 'tls', sni: json.sni, name: json.ps, ...json
    });
  } catch (_) {}
  return null;
}

function tryParseVLess(uri) {
  if (!uri.startsWith('vless://')) return null;
  try {
    const m = uri.match(/^vless:\/\/(.+)@(.+):(\d+)\/?(?:\?([^#]*))?(?:#(.+))?$/);
    if (!m) return null;
    const [, password, server, port, query, name] = m;
    const params = parseQuery(query);
    return buildNode('vless', server, parseInt(port), { password, name: name || params.remarks, ...params });
  } catch (_) {}
  return null;
}

function tryParseTrojan(uri) {
  if (!uri.startsWith('trojan://')) return null;
  try {
    const m = uri.match(/^trojan:\/\/(.+)@(.+):(\d+)\/?(?:\?([^#]*))?(?:#(.+))?$/);
    if (!m) return null;
    const [, password, server, port, query, name] = m;
    const params = parseQuery(query);
    return buildNode('trojan', server, parseInt(port), { password, name: name || params.remarks, ...params });
  } catch (_) {}
  return null;
}

function tryParseHysteria(uri) {
  // hysteria:// or hy2:// or hysteria2://
  if (!uri.match(/^(hysteria|hy2|hysteria2):\/\//)) return null;
  try {
    const m = uri.match(/^(hysteria2?|hy2):\/\/([^@]+)@([^:]+):(\d+)\/?(?:\?([^#]*))?(?:#(.+))?$/);
    if (!m) return null;
    const [, proto, password, server, port, query, name] = m;
    const params = parseQuery(query);
    const type = proto.startsWith('hy') ? 'hysteria2' : 'hysteria';
    return buildNode(type, server, parseInt(port), { password, name: name || params.remarks, ...params });
  } catch (_) {}
  return null;
}

function tryParseAnyTLS(uri) {
  if (!uri.startsWith('anytls://')) return null;
  try {
    const m = uri.match(/^anytls:\/\/(.+)@(.+):(\d+)\/?(?:\?([^#]*))?(?:#(.+))?$/);
    if (!m) return null;
    const [, password, server, port, query, name] = m;
    const params = parseQuery(query);
    return buildNode('anytls', server, parseInt(port), { password, name: decodeURIComponent(name || params.remarks || `${server}:${port}`), ...params });
  } catch (_) {}
  return null;
}

function tryParseTUIC(uri) {
  if (!uri.startsWith('tuic://')) return null;
  try {
    const m = uri.match(/^tuic:\/\/(.+)@(.+):(\d+)\/?(?:\?([^#]*))?(?:#(.+))?$/);
    if (!m) return null;
    const [, password, server, port, query, name] = m;
    const params = parseQuery(query);
    return buildNode('tuic', server, parseInt(port), { password, name: name || params.remarks, ...params });
  } catch (_) {}
  return null;
}

function parseQuery(q) {
  const p = {};
  if (!q) return p;
  for (const part of q.split('&')) {
    const [k, v] = part.split('=');
    if (k) p[k] = v ? decodeURIComponent(v) : '';
  }
  return p;
}

function buildNode(type, server, port, extras) {
  const rawName = extras.name || extras.remarks || `${server}:${port}`;
  return {
    name: rawName,  // 原始名称（匹配 subconverter）
    rawName,
    server, port, type,
    password: extras.password || extras.uuid || extras.id || '',
    cipher: extras.cipher || extras.method || '',
    udp: extras.udp !== '0' && extras.udp !== false,
    fingerprint: extras.fp || extras.fingerprint || 'chrome',
    sni: extras.sni || extras.peer || server,
    'skip-cert-verify': extras.insecure === '1' || extras.allowInsecure === '1' || extras['skip-cert-verify'] || false,
    alpn: extras.alpn ? extras.alpn.split(',') : undefined,
  };
}

// ═══════════════════════════════════════════
//  节点名增强（国旗 emoji + 区域检测）
// ═══════════════════════════════════════════

const REGION_MAP = [
  ['香港', '🇭🇰'], ['台湾', '🇨🇳'], ['日本', '🇯🇵'], ['美国', '🇺🇸'],
  ['韩国', '🇰🇷'], ['新加坡', '🇸🇬'], ['英国', '🇬🇧'], ['德国', '🇩🇪'],
  ['印度', '🇮🇳'], ['越南', '🇻🇳'], ['泰国', '🇹🇭'], ['菲律宾', '🇵🇭'],
  ['加拿大', '🇨🇦'], ['澳大利亚', '🇦🇺'], ['澳门', '🇲🇴'], ['埃及', '🇪🇬'],
  ['缅甸', '🇲🇲'], ['蒙古', '🇲🇳'], ['老挝', '🇱🇦'], ['文莱', '🇧🇳'],
  ['巴基斯坦', '🇵🇰'], ['马来西亚', '🇲🇾'], ['柬埔寨', '🇰🇭'],
  ['意大利', '🇮🇹'], ['法国', '🇫🇷'], ['巴西', '🇧🇷'], ['阿根廷', '🇦🇷'],
  ['俄罗斯', '🇷🇺'], ['土耳其', '🇹🇷'], ['印度尼西亚', '🇮🇩'],
];

function detectRegion(name) {
  for (const [kw, flag] of REGION_MAP) {
    if (name.includes(kw)) return { kw, flag };
  }
  return null;
}

function enhanceNodeName(node) {
  const region = detectRegion(node.rawName);
  if (region && !node.rawName.startsWith(region.flag)) {
    node.name = region.flag + ' ' + node.rawName;
  }
  node.region = region ? region.kw : null;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const p = url.pathname;

    if (p === '/health') return new Response('OK');

    if (p === '/sub') {
      const rawUrl = url.searchParams.get('url');
      const mode = url.searchParams.get('mode') || 'inline';
      if (!rawUrl) return new Response('Missing url param', { status: 400 });

      try {
        // 1. 拉取并解析订阅
        const nodes = await fetchNodes(decodeURIComponent(rawUrl));
        if (!nodes.length) return new Response('No nodes found', { status: 400 });
        globalThis._nodes = nodes;

        // 2. 拉取规则
        const ruleData = await fetchRules();

        // 3. 组装配置
        const result = (mode === 'provider')
          ? buildProviderConfig(nodes, ruleData, url.origin, rawUrl)
          : buildInlineConfig(nodes, ruleData);

        return new Response(result, {
          headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=300' }
        });
      } catch (e) {
        return new Response(`Error: ${e.message}`, { status: 502 });
      }
    }

    if (p === '/list') {
      const rawUrl = url.searchParams.get('url');
      if (!rawUrl) return new Response('Missing url', { status: 400 });
      const nodes = await fetchNodes(decodeURIComponent(rawUrl));
      const yaml = ['proxies:'];
      for (const n of nodes) yaml.push(`  - {name: ${JSON.stringify(n.rawName)}, server: ${n.server}, port: ${n.port}, type: ${n.type}, password: ${JSON.stringify(n.password)}, fingerprint: ${n.fingerprint}, sni: ${n.sni}, skip-cert-verify: ${n['skip-cert-verify']}, udp: ${n.udp}}`);
      return respond(yaml.join('\n'), 300);
    }

    if (p.startsWith('/rules/')) {
      const hash = p.split('/rules/')[1].replace('.yaml', '');
      const cached = RULE_STORE.get(hash);
      return cached ? respond(cached, 86400) : new Response('Not found', { status: 404 });
    }

    return new Response('ProxyPress v4', { status: 404 });
  }
};

// ═══════════════════════════════════════════
//  数据
// ═══════════════════════════════════════════

const RULE_STORE = new Map();
const RULESETS = {
  '🎯 全球直连': ['LocalAreaNetwork.list','UnBan.list','GoogleCN.list','ChinaDomain.list','ChinaCompanyIp.list','Download.list'],
  '🛑 广告拦截': ['BanAD.list'],
  '🍃 应用净化': ['BanProgramAD.list'],
  '📢 谷歌FCM': ['Ruleset/GoogleFCM.list'],
  'Ⓜ️ 微软Bing': ['Bing.list'], 'Ⓜ️ 微软云盘': ['OneDrive.list'], 'Ⓜ️ 微软服务': ['Microsoft.list'],
  '🍎 苹果服务': ['Apple.list'], '📲 电报消息': ['Telegram.list'],
  '📹 油管视频': ['Ruleset/YouTube.list'], '🎥 奈飞视频': ['Ruleset/Netflix.list'],
  '📺 哔哩哔哩': ['Ruleset/Bilibili.list','Ruleset/BilibiliHMT.list'],
  '🌍 国外媒体': ['ProxyMedia.list'], '🌏 国内媒体': ['ChinaMedia.list'],
  '🎶 网易音乐': ['Ruleset/NetEaseMusic.list'],
  '💬 Ai平台': ['Ruleset/AI.list','Ruleset/OpenAi.list'],
  '🎮 游戏平台': ['Ruleset/Steam.list','Ruleset/Epic.list','Ruleset/Sony.list','Ruleset/Nintendo.list'],
};
const BASE = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/';

// ═══════════════════════════════════════════
//  网络
// ═══════════════════════════════════════════

async function fetchNodes(decodedUrl) {
  const resp = await fetch(decodedUrl, { headers: { 'User-Agent': 'ProxyPress/4.0', 'Accept': '*/*' } });
  let body = await resp.text();
  // base64 解码
  if (/^[A-Za-z0-9+/=\s]+$/.test(body.trim()) && body.length > 50 && !body.includes('<')) {
    try { const bin = atob(body.replace(/\s/g, '')); if (bin.includes('://')) body = bin; } catch (_) {}
  }
  const nodes = [];
  for (const line of body.split('\n')) {
    const n = parseNode(line.trim());
    if (n) { enhanceNodeName(n); nodes.push(n); }
  }
  return nodes;
}

async function fetchRules() {
  const rules = [];
  const promises = [];
  for (const [group, files] of Object.entries(RULESETS)) {
    for (const f of files) {
      promises.push(
        fetch(BASE + f, { headers: { 'User-Agent': 'ProxyPress/4.0' } })
          .then(r => r.text())
          .then(t => {
            for (const line of t.split('\n')) {
              const s = line.trim();
              if (!s || s.startsWith('#')) continue;
              // 如果规则不带 target group，补上 ruleset 的组名
              const parts = s.split(',');
              const last = parts[parts.length - 1].trim();
              // no-resolve 是选项不是组名，也需要补
              if (last === 'no-resolve' || last === 'src' || last === 'dst' || !last) {
                rules.push({ group, line: s + ',' + group });
              } else if (parts.length >= 3) {
                // 已有组名（如 DOMAIN-SUFFIX,domain,组名）
                rules.push({ group, line: s });
              } else {
                // 缺组名，补上
                rules.push({ group, line: s + ',' + group });
              }
            }
          }).catch(() => {})
      );
    }
  }
  await Promise.all(promises);
  rules.push({ group: '🎯 全球直连', line: 'GEOIP,CN,🎯 全球直连' });
  rules.push({ group: '🐟 漏网之鱼', line: 'MATCH,🐟 漏网之鱼' });
  return rules;
}

// ═══════════════════════════════════════════
//  配置构建
// ═══════════════════════════════════════════

function formatNodeLine(n) {
  // 使用 rawName（无 emoji），匹配 subconverter 输出
  return `  - {name: ${JSON.stringify(n.rawName)}, server: ${n.server}, port: ${n.port}, type: ${n.type}, password: ${JSON.stringify(n.password)}, cipher: ${JSON.stringify(n.cipher)}, udp: ${n.udp}, fingerprint: ${n.fingerprint}, sni: ${n.sni}, skip-cert-verify: ${n['skip-cert-verify']}}`;
}

function buildInlineConfig(nodes, rules) {
  const names = nodes.map(n => n.name);
  const lines = ['port: 7890', 'socks-port: 7891', 'allow-lan: true', 'mode: Rule', 'log-level: info', '', 'proxies:'];
  for (const n of nodes) lines.push(formatNodeLine(n));
  lines.push(...buildGroups(names), ...buildRules(rules));
  return lines.join('\n');
}

function buildProviderConfig(nodes, rules, host, rawSubUrl) {
  const names = nodes.map(n => n.name);
  const lines = [
    'port: 7890', 'socks-port: 7891', 'allow-lan: true', 'mode: Rule', 'log-level: info', '',
    'proxy-providers:',
    '  provider:',
    '    type: http',
    '    path: ./proxy-providers/provider.yaml',
    `    url: ${host}/list?url=${encodeURIComponent(decodeURIComponent(rawSubUrl))}`,
    '    interval: 86400',
    '    health-check:',
    '      enable: true',
    '      url: http://www.gstatic.com/generate_204',
    '      interval: 300',
    '',
    'rule-providers:',
  ];

  const ruleGroups = {};
  for (const r of rules) {
    if (!ruleGroups[r.group]) ruleGroups[r.group] = [];
    ruleGroups[r.group].push(r.line);
  }
  const ruleRefs = [];
  for (const [group, rlines] of Object.entries(ruleGroups)) {
    const content = rlines.join('\n');
    const hash = simpleHash(content);
    const name = sanitize(group);
    RULE_STORE.set(hash, content);
    lines.push(`  ${name}:`, '    type: http', '    behavior: classical', `    path: ./rulesets/${name}.yaml`, `    url: ${host}/rules/${hash}.yaml`, '    interval: 86400');
    ruleRefs.push(`  - RULE-SET,${name},${group}`);
  }

  lines.push('');
  lines.push(...buildGroupsWithProvider(names));
  lines.push('', 'rules:');
  lines.push(...ruleRefs);
  return lines.join('\n');
}

function buildGroups(names) {
  const lines = ['', 'proxy-groups:'];
  const allNodes = globalThis._nodes || [];
  const regionSet = new Map();
  for (const n of allNodes) {
    if (n.region && !regionSet.has(n.region)) {
      const flag = REGION_MAP.find(r => r[0] === n.region)?.[1] || '';
      regionSet.set(n.region, flag);
    }
  }
  
  // 🚀 节点选择 — 只引用组名（匹配 subconverter）
  lines.push('  - name: 🚀 节点选择', '    type: select', '    proxies:');
  lines.push('      - ♻️ 自动选择');
  for (const [region, flag] of regionSet) {
    lines.push(`      - ${flag} ${region}节点`);
  }
  lines.push('      - 🚀 手动切换');
  lines.push('      - DIRECT');
  
  // 🚀 手动切换 — 列出所有节点原名
  lines.push('  - name: 🚀 手动切换', '    type: select', '    proxies:');
  for (const n of allNodes) lines.push(`      - ${n.rawName}`);
  lines.push('      - DIRECT');
  
  // ♻️ 自动选择 — 列出所有节点原名
  lines.push('  - name: ♻️ 自动选择', '    type: url-test', '    proxies:');
  for (const n of allNodes) lines.push(`      - ${n.rawName}`);
  lines.push('    url: http://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 50');
  
  // 区域组 — 每个区域的节点原名
  for (const [region, flag] of regionSet) {
    const gname = `${flag} ${region}节点`;
    const regionNodes = allNodes.filter(n => n.region === region);
    if (regionNodes.length > 0) {
      lines.push(`  - name: ${gname}`, '    type: url-test', '    proxies:');
      for (const n of regionNodes) lines.push(`      - ${n.rawName}`);
      lines.push('    url: http://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 50');
    }
  }
  
  addTargetGroups(lines);
  return lines;
}

function buildGroupsWithProvider(names) {
  const lines = ['proxy-groups:'];
  const allNodes = globalThis._nodes || [];
  
  const regionSet = new Map();
  for (const n of allNodes) {
    if (n.region && !regionSet.has(n.region)) {
      const flag = REGION_MAP.find(r => r[0] === n.region)?.[1] || '';
      regionSet.set(n.region, flag);
    }
  }
  
  // 🚀 节点选择 — 只引用组名
  lines.push('  - name: 🚀 节点选择', '    type: select', '    proxies:');
  lines.push('      - ♻️ 自动选择');
  for (const [region, flag] of regionSet) {
    lines.push(`      - ${flag} ${region}节点`);
  }
  lines.push('      - 🚀 手动切换');
  lines.push('      - DIRECT');

  // 🚀 手动切换 — 保持内联（手动选择必须用原名）
  lines.push('  - name: 🚀 手动切换', '    type: select', '    proxies:');
  for (const n of allNodes) lines.push(`      - ${n.rawName}`);
  lines.push('      - DIRECT');

  // ♻️ 自动选择 — 使用 provider
  lines.push('  - name: ♻️ 自动选择', '    type: url-test',
    '    use:', '      - provider',
    '    url: http://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 50');

  // 区域过滤组 — 使用 provider + filter
  for (const [region, flag] of regionSet) {
    const gname = `${flag} ${region}节点`;
    lines.push(`  - name: ${gname}`, '    type: url-test',
      '    use:', '      - provider',
      `    filter: "${region}"`,
      '    url: http://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 50');
  }

  addTargetGroups(lines);
  return lines;
}

function addTargetGroups(lines) {
  const groups = ['🎯 全球直连','🛑 广告拦截','🍃 应用净化','🐟 漏网之鱼','📲 电报消息','📹 油管视频','🎥 奈飞视频','📺 哔哩哔哩','🌍 国外媒体','🌏 国内媒体','📢 谷歌FCM','Ⓜ️ 微软Bing','Ⓜ️ 微软云盘','Ⓜ️ 微软服务','🍎 苹果服务','🎶 网易音乐','💬 Ai平台','🎮 游戏平台'];
  for (const t of groups) {
    if (t === '🎯 全球直连') lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - DIRECT', '      - 🚀 节点选择');
    else if (t === '🛑 广告拦截' || t === '🍃 应用净化') lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - REJECT', '      - DIRECT');
    else if (t === '🐟 漏网之鱼') lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - 🚀 节点选择', '      - DIRECT', '      - ♻️ 自动选择');
    else lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - 🚀 节点选择', '      - ♻️ 自动选择', '      - DIRECT');
  }
}

function buildRules(rules) {
  const lines = ['', 'rules:'];
  for (const r of rules) lines.push(`  - ${r.line}`);
  return lines;
}

function sanitize(s) { return s.replace(/[^\w\u4e00-\u9fff]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'other'; }
function simpleHash(s) { let h = 0; for (let i = 0; i < s.length; i++) { h = ((h << 5) - h) + s.charCodeAt(i); h |= 0; } return Math.abs(h).toString(16).padStart(8,'0').slice(0,8); }
function respond(body, maxAge) { return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': `public, max-age=${maxAge}` } }); }
