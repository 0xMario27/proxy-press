// ═══════════════════════════════════════════════════════════
//  常量（平台无关）
// ═══════════════════════════════════════════════════════════

const RULE_STORE = new Map();  // hash → YAML 内容
const BASE_RULES_URL = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/';

// 区域识别
const REGION_MAP = [
  ['香港', '🇭🇰'], ['台湾', '🇨🇳'], ['日本', '🇯🇵'], ['美国', '🇺🇸'],
  ['韩国', '🇰🇷'], ['新加坡', '🇸🇬'], ['英国', '🇬🇧'], ['德国', '🇩🇪'],
  ['印度', '🇮🇳'], ['越南', '🇻🇳'], ['泰国', '🇹🇭'], ['菲律宾', '🇵🇭'],
  ['加拿大', '🇨🇦'], ['澳大利亚', '🇦🇺'], ['澳门', '🇲🇴'],
  ['马来西亚', '🇲🇾'], ['俄罗斯', '🇷🇺'], ['土耳其', '🇹🇷'],
  ['印度尼西亚', '🇮🇩'], ['巴西', '🇧🇷'], ['阿根廷', '🇦🇷'],
  ['法国', '🇫🇷'], ['意大利', '🇮🇹'],
];

// ═══════════════════════════════════════════════════════════
//  网络工具
// ═══════════════════════════════════════════════════════════



function isBase64(str) {
  return /^[A-Za-z0-9+/=\s\r\n]+$/.test(str.trim()) && str.length > 50 && !str.includes('<');
}

function base64Decode(str) {
  try { return Buffer.from(str.replace(/\s/g, ''), 'base64').toString('utf-8'); }
  catch { return str; }
}

// ═══════════════════════════════════════════════════════════
//  配置解析 (.ini 文件)
// ═══════════════════════════════════════════════════════════

// 解析 ruleset=组名,url
function parseRulesets(iniContent) {
  const rulesets = [];
  const re = /^ruleset\s*=\s*(.+?)\s*,\s*(.+)/gm;
  let m;
  while ((m = re.exec(iniContent)) !== null) {
    rulesets.push({ group: m[1].trim(), url: m[2].trim() });
  }
  return rulesets;
}

// 解析 custom_proxy_group=组名`类型`[...]
function parseCustomProxyGroups(iniContent) {
  const groups = [];
  // 匹配: custom_proxy_group=组名`类型`[...内容...]
  const re = /^custom_proxy_group\s*=\s*(.+?)`(.+?)`(.*)/gm;
  let m;
  while ((m = re.exec(iniContent)) !== null) {
    const name = m[1].trim();
    const type = m[2].trim();
    const rawRest = m[3].trim();

    // 解析 []内容 和 filter
    const items = [];
    let filter = '';
    if (type === 'url-test' || type === 'fallback') {
      // 格式: filter`url`interval`tolerance`...
      const parts = rawRest.split('`');
      filter = parts[0] || '';
      items.push({ filter });
      for (let i = 1; i < parts.length; i += 3) {
        const pUrl = parts[i] || '';
        const pInterval = parts[i + 1] || '300';
        const pTolerance = parts[i + 2] || '50';
        items.push({ url: pUrl, interval: pInterval, tolerance: pTolerance });
      }
    } else {
      // select 类型: 解析 []item1`[]item2`...
      const itemRe = /\[\]([^`\n]+)/g;
      let im;
      while ((im = itemRe.exec('[]' + rawRest)) !== null) {
        items.push(im[1].trim());
      }
    }

    groups.push({ name, type, items, filter, raw: rawRest });
  }
  return groups;
}

// ═══════════════════════════════════════════════════════════
//  规则获取
// ═══════════════════════════════════════════════════════════

function processRuleText(text, group, rules) {
  // 过滤明显的 HTTP 错误页面内容
  if (/^<[!]?DOCTYPE|^<html|<head|<body|Not Found|^[0-9]{3}:/.test(text.trim())) return;
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (!s || s.startsWith('#') || s.startsWith(';')) continue;
    // 跳过非规则行
    if (!/^(DOMAIN|IP-CIDR|GEOIP|MATCH|RULE-SET|DST-PORT|SRC-PORT|PROCESS-NAME|AND|OR|NOT|URL-REGEX|SRC-IP)/i.test(s)) continue;
    const parts = s.split(',');
    const last = parts[parts.length - 1].trim();
    if (last === 'no-resolve' || last === 'src' || last === 'dst' || !last) {
      rules.push({ group, line: s + ',' + group });
    } else if (parts.length >= 3) {
      rules.push({ group, line: s });
    } else {
      rules.push({ group, line: s + ',' + group });
    }
  }
}

// ═══════════════════════════════════════════════════════════
//  订阅获取与解析
// ═══════════════════════════════════════════════════════════



// ═══════════════════════════════════════════════════════════
//  节点增强
// ═══════════════════════════════════════════════════════════

function detectRegion(name) {
  for (const [kw, flag] of REGION_MAP) {
    if (name.includes(kw)) return { kw, flag };
  }
  return null;
}

function enhanceNodes(nodes) {
  for (const n of nodes) {
    n.rawName = n.name;
    const region = detectRegion(n.name);
    if (region && !n.name.startsWith(region.flag)) {
      n.name = region.flag + ' ' + n.name;
    }
    n.region = region ? region.kw : null;
  }
  return nodes;
}

// ═══════════════════════════════════════════════════════════
//  Clash 配置构建
// ═══════════════════════════════════════════════════════════

function simpleHash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) { h = ((h << 5) - h) + s.charCodeAt(i); h |= 0; }
  return Math.abs(h).toString(16).padStart(8, '0').slice(0, 8);
}

function sanitize(s) {
  return s.replace(/[^\w\u4e00-\u9fff]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'other';
}

// 紧凑 flow-style（/list provider 用，Clash 核心解析器兼容）
function formatNodeCompact(n) {
  const f = [];
  f.push(`name: ${JSON.stringify(n.rawName)}`);
  f.push(`type: ${n.type}`);
  f.push(`server: ${n.server}`);
  f.push(`port: ${n.port}`);
  const pwd = n.password || n.uuid || '';
  if (pwd) f.push(`password: ${JSON.stringify(pwd)}`);
  if (n.cipher && n.cipher !== 'auto') f.push(`cipher: ${JSON.stringify(n.cipher)}`);
  if (n.udp) f.push('udp: true');
  if (n['skip-cert-verify']) f.push('skip-cert-verify: true');
  const sn = n.sni || n.servername || '';
  if (sn && sn !== n.server) f.push(`servername: ${JSON.stringify(sn)}`);
  if (n.tls && n.tls !== 'none') {
    f.push('tls: true');
    if (n.alpn && n.alpn.length) f.push(`alpn: [${n.alpn}]`);
  }
  if (n.network && n.network !== 'tcp') {
    f.push(`network: ${n.network}`);
    if (n.host) f.push(`host: ${JSON.stringify(n.host)}`);
    if (n.path && n.path !== '/') f.push(`path: ${JSON.stringify(n.path)}`);
  }
  if (n.fingerprint && n.fingerprint !== 'chrome') f.push(`client-fingerprint: ${JSON.stringify(n.fingerprint)}`);
  return `  - {${f.join(', ')}}`;
}

// block-style YAML（主配置 inline 模式用，Stash 兼容）
function formatNodeBlockYaml(n) {
  const lines = [];
  lines.push(`  - name: ${JSON.stringify(n.rawName)}`);
  lines.push(`    type: ${n.type}`);
  lines.push(`    server: ${n.server}`);
  lines.push(`    port: ${n.port}`);
  // 密码
  const pwd = n.password || n.uuid || '';
  if (pwd) lines.push(`    password: ${JSON.stringify(pwd)}`);
  // 加密（仅 ss/ssr）
  if (n.cipher && n.cipher !== 'auto') lines.push(`    cipher: ${JSON.stringify(n.cipher)}`);
  // UDP
  if (n.udp) lines.push('    udp: true');
  // skip-cert-verify
  if (n['skip-cert-verify']) lines.push('    skip-cert-verify: true');
  // SNI（sni 或 servername，不同于 server 时才写）
  const sn = n.sni || n.servername || '';
  if (sn && sn !== n.server) lines.push(`    servername: ${JSON.stringify(sn)}`);
  // TLS
  if (n.tls && n.tls !== 'none') {
    lines.push('    tls: true');
    if (n.alpn && n.alpn.length) lines.push(`    alpn: [${n.alpn}]`);
  }
  // 传输层（仅非 tcp）
  if (n.network && n.network !== 'tcp') {
    lines.push(`    network: ${n.network}`);
    if (n.network === 'ws') {
      lines.push('    ws-opts:');
      if (n.path) lines.push(`      path: ${JSON.stringify(n.path)}`);
      if (n.host) lines.push(`      headers:\n        Host: ${JSON.stringify(n.host)}`);
    } else if (n.network === 'grpc') {
      lines.push('    grpc-opts:');
      if (n.path) lines.push(`      grpc-service-name: ${JSON.stringify(n.path)}`);
    } else if (n.network === 'h2') {
      lines.push('    h2-opts:');
      if (n.host) lines.push(`      host: [${JSON.stringify(n.host)}]`);
      if (n.path) lines.push(`      path: ${JSON.stringify(n.path)}`);
    }
  }
  // 指纹
  if (n.fingerprint && n.fingerprint !== 'chrome') lines.push(`    client-fingerprint: ${JSON.stringify(n.fingerprint)}`);
  // VLESS flow
  if (n.flow) lines.push(`    flow: ${JSON.stringify(n.flow)}`);
  // Hysteria up/down
  if (n.upMbps) lines.push(`    up: ${JSON.stringify(n.upMbps)}`);
  if (n.downMbps) lines.push(`    down: ${JSON.stringify(n.downMbps)}`);
  // obfs (hysteria)
  if (n.obfs && n.type !== 'ssr') lines.push(`    obfs: ${JSON.stringify(n.obfs)}`);
  if (n.obfsPassword) lines.push(`    obfs-password: ${JSON.stringify(n.obfsPassword)}`);
  return lines.join('\n');
}

function buildProviderConfig(nodes, ruleData, host, rawSubUrl) {
  const lines = [
    'port: 7890', 'socks-port: 7891', 'allow-lan: true',
    'mode: Rule', 'log-level: info', '',
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
  ];
  lines.push(...buildGroupsWithProvider(nodes));
  lines.push('', 'rules:');
  lines.push(...buildRuleRefs(ruleData));
  // rule-providers 放在 rules 之后
  lines.push('');
  lines.push(...buildRuleProviders(ruleData, host));
  return lines.join('\n');
}

function buildInlineConfig(nodes, ruleData, host) {
  const lines = [
    'port: 7890', 'socks-port: 7891', 'allow-lan: true',
    'mode: Rule', 'log-level: info', '',
    'proxies:'
  ];
  for (const n of nodes) lines.push(formatNodeCompact(n));
  lines.push('');
  lines.push(...buildGroupsInline(nodes));
  // Stash 兼容的 rules + rule-providers
  lines.push('', 'rules:');
  lines.push(...buildRuleRefs(ruleData));
  lines.push('');
  lines.push(...buildRuleProviders(ruleData, host));
  return lines.join('\n');
}

// 共享：生成 Stash 兼容的 rule-providers（按 domain/ipcidr 拆分）
function buildRuleProviders(ruleData, host) {
  if (!ruleData.length) return [];
  
  // 按 group + 类型拆分为 domain 和 ipcidr 两个 provider
  const domainRules = {};  // { group: [value, ...] }
  const ipcidrRules = {};  // { group: [value, ...] }
  const otherRules = [];   // MATCH, PROCESS-NAME 等保留为内联

  for (const r of ruleData) {
    const parts = r.line.split(',');
    const ruleType = parts[0].trim().toUpperCase();
    const ruleValue = parts[1] ? parts[1].trim() : '';
    const group = r.group;

    if (ruleType === 'DOMAIN' || ruleType === 'DOMAIN-SUFFIX' || 
        ruleType === 'DOMAIN-KEYWORD' || ruleType === 'URL-REGEX') {
      let val = ruleValue;
      if (ruleType === 'DOMAIN-SUFFIX') val = '+.' + val;  // Stash: +. 前缀表示 suffix
      if (!domainRules[group]) domainRules[group] = [];
      domainRules[group].push(val);
    } else if (ruleType === 'IP-CIDR' || ruleType === 'IP-CIDR6' || ruleType === 'GEOIP') {
      if (!ipcidrRules[group]) ipcidrRules[group] = [];
      ipcidrRules[group].push(ruleType === 'GEOIP' ? ruleValue : ruleValue);
      // GEOIP,CN → 存为 "CN"（但 Stash ipcidr 行为可能不支持 GEOIP，保留原值）
      if (ruleType === 'GEOIP') ipcidrRules[group].push(ruleValue);
      else ipcidrRules[group].push(ruleValue);
    } else {
      // MATCH, PROCESS-NAME, DST-PORT 等保留为内联 rule
      otherRules.push(r);
    }
  }

  const lines = [];
  if (Object.keys(domainRules).length > 0 || Object.keys(ipcidrRules).length > 0) {
    lines.push('rule-providers:');
  }

  // 为每个 group 生成 domain provider
  for (const [group, values] of Object.entries(domainRules)) {
    const content = values.join('\n');
    const hash = simpleHash(content);
    const name = sanitize(group) + '_domain';
    RULE_STORE.set(hash, content);
    lines.push(`  ${name}: {behavior: domain, format: text, path: ./rulesets/${name}.txt, url: ${host}/rules/${hash}.yaml, interval: 86400}`);
  }

  // 为每个 group 生成 ipcidr provider
  for (const [group, values] of Object.entries(ipcidrRules)) {
    const content = values.join('\n');
    const hash = simpleHash(content);
    const name = sanitize(group) + '_ipcidr';
    RULE_STORE.set(hash, content);
    lines.push(`  ${name}: {behavior: ipcidr, format: text, path: ./rulesets/${name}.txt, url: ${host}/rules/${hash}.yaml, interval: 86400}`);
  }

  return lines;
}

// 共享：生成 RULE-SET 引用列表（Stash 兼容）
function buildRuleRefs(ruleData) {
  if (!ruleData.length) return [];
  const refs = new Set();
  const otherRefs = [];

  for (const r of ruleData) {
    const parts = r.line.split(',');
    const ruleType = parts[0].trim().toUpperCase();
    const ruleValue = parts[1] ? parts[1].trim() : '';
    const group = r.group;
    const name = sanitize(group);

    if (ruleType === 'DOMAIN' || ruleType === 'DOMAIN-SUFFIX' || 
        ruleType === 'DOMAIN-KEYWORD' || ruleType === 'URL-REGEX') {
      refs.add(`  - RULE-SET,${name}_domain,${group}`);
    } else if (ruleType === 'IP-CIDR' || ruleType === 'IP-CIDR6' || ruleType === 'GEOIP') {
      refs.add(`  - RULE-SET,${name}_ipcidr,${group}` + (parts[parts.length-1].trim() === 'no-resolve' ? ',no-resolve' : ''));
    } else {
      // 内联规则直接写入
      otherRefs.push(`  - ${r.line}`);
    }
  }

  return [...refs, ...otherRefs];
}

function quoteYaml(s) {
  // 名含 YAML 特殊字符时加引号
  if (/[\[\]{}:,#&*?|><=!%@`"']/.test(s)) return JSON.stringify(s);
  return s;
}

function buildGroupsWithProvider(nodes) {
  const lines = ['proxy-groups:'];
  const regionSet = new Map();
  for (const n of nodes) {
    if (n.region && !regionSet.has(n.region)) {
      const flag = REGION_MAP.find(r => r[0] === n.region)?.[1] || '';
      regionSet.set(n.region, flag);
    }
  }

  // 🚀 节点选择
  lines.push('  - name: 🚀 节点选择', '    type: select', '    proxies:');
  lines.push('      - ♻️ 自动选择');
  for (const [region, flag] of regionSet) {
    lines.push(`      - ${flag} ${region}节点`);
  }
  lines.push('      - 🚀 手动切换', '      - DIRECT');

  // 🚀 手动切换 — 使用 provider（拉取全部节点，避免名称不匹配）
  lines.push('  - name: 🚀 手动切换', '    type: select',
    '    use:', '      - provider',
    '    proxies:', '      - DIRECT');

  // ♻️ 自动选择 (使用 provider)
  lines.push('  - name: ♻️ 自动选择', '    type: url-test',
    '    use:', '      - provider',
    '    url: http://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 50');

  // 区域组 (provider + filter)
  for (const [region, flag] of regionSet) {
    const gname = `${flag} ${region}节点`;
    lines.push(`  - name: ${gname}`, '    type: url-test',
      '    use:', '      - provider',
      `    filter: "${region}"`,
      '    url: http://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 50');
  }

  addTargetGroups(lines, regionSet);
  return lines;
}

function buildGroupsInline(nodes) {
  const lines = ['', 'proxy-groups:'];
  const regionSet = new Map();
  for (const n of nodes) {
    if (n.region && !regionSet.has(n.region)) {
      const flag = REGION_MAP.find(r => r[0] === n.region)?.[1] || '';
      regionSet.set(n.region, flag);
    }
  }

  lines.push('  - name: 🚀 节点选择', '    type: select', '    proxies:');
  lines.push('      - ♻️ 自动选择');
  for (const [region, flag] of regionSet) {
    lines.push(`      - ${flag} ${region}节点`);
  }
  lines.push('      - 🚀 手动切换', '      - DIRECT');

  lines.push('  - name: 🚀 手动切换', '    type: select', '    proxies:');
  for (const n of nodes) lines.push(`      - ${quoteYaml(n.rawName)}`);
  lines.push('      - DIRECT');

  lines.push('  - name: ♻️ 自动选择', '    type: url-test', '    proxies:');
  for (const n of nodes) lines.push(`      - ${quoteYaml(n.rawName)}`);
  lines.push('    url: http://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 50');

  for (const [region, flag] of regionSet) {
    const gname = `${flag} ${region}节点`;
    const regionNodes = nodes.filter(n => n.region === region);
    if (regionNodes.length > 0) {
      lines.push(`  - name: ${gname}`, '    type: url-test', '    proxies:');
      for (const n of regionNodes) lines.push(`      - ${quoteYaml(n.rawName)}`);
      lines.push('    url: http://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 50');
    }
  }

  addTargetGroups(lines, regionSet);
  return lines;
}

function addTargetGroups(lines, regionSet) {
  // 把 regionSet 转成有序的组名列表
  const regionGroupNames = [];
  for (const [region, flag] of regionSet) {
    regionGroupNames.push(`${flag} ${region}节点`);
  }

  const groups = [
    '🎯 全球直连', '🛑 广告拦截', '🍃 应用净化', '🐟 漏网之鱼',
    '📲 电报消息', '📹 油管视频', '🎥 奈飞视频', '📺 哔哩哔哩',
    '🌍 国外媒体', '🌏 国内媒体', '📢 谷歌FCM',
    'Ⓜ️ 微软Bing', 'Ⓜ️ 微软云盘', 'Ⓜ️ 微软服务',
    '🍎 苹果服务', '🎶 网易音乐', '💬 Ai平台', '🎮 游戏平台'
  ];
  for (const t of groups) {
    if (t === '🎯 全球直连') {
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - DIRECT', '      - 🚀 节点选择');
    } else if (t === '🛑 广告拦截' || t === '🍃 应用净化') {
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - REJECT', '      - DIRECT');
    } else if (t === '🌏 国内媒体' || t === '📺 哔哩哔哩' || t === '🎶 网易音乐'
               || t === 'Ⓜ️ 微软Bing' || t === 'Ⓜ️ 微软云盘' || t === 'Ⓜ️ 微软服务'
               || t === '🍎 苹果服务') {
      // 国内/有国内CDN的服务默认直连
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:');
      lines.push('      - DIRECT');
      lines.push('      - 🚀 节点选择');
      lines.push('      - ♻️ 自动选择');
      for (const gn of regionGroupNames) lines.push(`      - ${gn}`);
    } else {
      // 其他组: 节点选择 + 自动选择 + 各地区组 + DIRECT
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:');
      lines.push('      - 🚀 节点选择');
      lines.push('      - ♻️ 自动选择');
      for (const gn of regionGroupNames) lines.push(`      - ${gn}`);
      lines.push('      - DIRECT');
    }
  }
}

function buildRules(ruleData) {
  const lines = ['', 'rules:'];
  for (const r of ruleData) lines.push(`  - ${r.line}`);
  return lines;
}

module.exports = {
  RULE_STORE, BASE_RULES_URL, REGION_MAP,
  isBase64, base64Decode,
  parseRulesets, parseCustomProxyGroups,
  processRuleText,
  detectRegion, enhanceNodes,
  simpleHash, sanitize,
  formatNodeCompact, formatNodeBlockYaml,
  buildProviderConfig, buildInlineConfig,
  buildRuleProviders, buildRuleRefs,
  quoteYaml,
  buildGroupsWithProvider, buildGroupsInline,
  addTargetGroups, buildRules,
};

