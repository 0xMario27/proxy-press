/**
 * formats.js — 多客户端格式输出器
 * 
 * 支持 target: clash | surge | quanx | loon | shadowrocket
 * 
 * 节点格式化规则（对标 subconverter 输出）:
 *   Surge:      [Proxy] / [Proxy Group] / [Rule] (INI)
 *   Quantumult X: [server_local] / [policy] / [filter_local] (INI)
 *   Loon:       [Proxy] / [Proxy Group] / [Rule] (INI, 与 Surge 类似)
 *   Shadowrocket: 每行一个原始协议链接（base64 编码）
 */

'use strict';

// ═══════════════════════════════════════════════════════════
//  节点 → 各格式字符串
// ═══════════════════════════════════════════════════════════

function formatNodeSurge(n) {
  const pwd = n.password || n.uuid || '';
  const name = n.rawName || n.name;

  switch (n.type) {
    case 'ss':
      return `${name} = ss, ${n.server}, ${n.port}, encrypt-method=${n.cipher || 'aes-256-gcm'}, password=${pwd}`;
    case 'ssr':
      return `${name} = ssr, ${n.server}, ${n.port}, encrypt-method=${n.cipher}, password=${pwd}, ssr-protocol=${n.protocol || 'origin'}, ssr-protocol-param=${n.protocolParam || ''}, obfs=${n.obfs || 'plain'}, obfs-host=${n.obfsParam || ''}`;
    case 'vmess':
      return `${name} = vmess, ${n.server}, ${n.port}, username=${pwd}, ws=${n.network === 'ws' ? 'true' : 'false'}, tls=${n.tls && n.tls !== 'none' ? 'true' : 'false'}${n.path && n.path !== '/' ? ', ws-path=' + n.path : ''}${n.host ? ', obfs-host=' + n.host : ''}${n.sni ? ', tls-host=' + n.sni : ''}${n['skip-cert-verify'] ? ', skip-cert-verify=true' : ''}`;
    case 'vless':
      return `${name} = vless, ${n.server}, ${n.port}, username=${pwd}, ws=${n.network === 'ws' ? 'true' : 'false'}, tls=${n.tls && n.tls !== 'none' ? 'true' : 'false'}${n.path ? ', ws-path=' + n.path : ''}${n.sni ? ', tls-host=' + n.sni : ''}`;
    case 'trojan':
      return `${name} = trojan, ${n.server}, ${n.port}, password=${pwd}${n.sni ? ', sni=' + n.sni : ''}${n['skip-cert-verify'] ? ', skip-cert-verify=true' : ''}`;
    case 'http':
    case 'https':
      return `${name} = http, ${n.server}, ${n.port}${n.username ? ', username=' + n.username : ''}${pwd ? ', password=' + pwd : ''}${n.tls ? ', tls=true' : ''}`;
    case 'socks5':
      return `${name} = socks5, ${n.server}, ${n.port}${n.username ? ', username=' + n.username : ''}${pwd ? ', password=' + pwd : ''}`;
    case 'hysteria':
      return `${name} = hysteria, ${n.server}, ${n.port}, auth=${pwd}${n.sni ? ', sni=' + n.sni : ''}${n.upMbps ? ', up=' + n.upMbps : ''}${n.downMbps ? ', down=' + n.downMbps : ''}${n['skip-cert-verify'] ? ', skip-cert-verify=true' : ''}`;
    case 'hysteria2':
      return `${name} = hysteria2, ${n.server}, ${n.port}, password=${pwd}${n.sni ? ', sni=' + n.sni : ''}${n.upMbps ? ', up=' + n.upMbps : ''}${n.downMbps ? ', down=' + n.downMbps : ''}${n['skip-cert-verify'] ? ', skip-cert-verify=true' : ''}${n.obfs ? ', obfs=' + n.obfs : ''}`;
    case 'tuic':
      return `${name} = tuic, ${n.server}, ${n.port}, token=${pwd}${n.uuid ? ', uuid=' + n.uuid : ''}${n.sni ? ', sni=' + n.sni : ''}${n.alpn ? ', alpn=' + n.alpn : ''}${n['skip-cert-verify'] ? ', skip-cert-verify=true' : ''}`;
    case 'anytls':
      return `${name} = anytls, ${n.server}, ${n.port}, password=${pwd}${n.sni ? ', sni=' + n.sni : ''}${n['skip-cert-verify'] ? ', skip-cert-verify=true' : ''}${n.alpn && n.alpn.length ? ', alpn=' + n.alpn.join(',') : ''}${n.fingerprint && n.fingerprint !== 'chrome' ? ', fingerprint=' + n.fingerprint : ''}`;
  }
}

function formatNodeQuanX(n) {
  const pwd = n.password || n.uuid || '';
  const name = n.rawName || n.name;
  const tag = name.replace(/[,=]/g, '_');

  switch (n.type) {
    case 'ss':
      return `shadowsocks=${n.server}:${n.port}, method=${n.cipher || 'aes-256-gcm'}, password=${pwd}, tag=${tag}`;
    case 'vmess':
      return `vmess=${n.server}:${n.port}, method=${n.cipher || 'auto'}, password=${pwd}, tag=${tag}${n.tls && n.tls !== 'none' ? ', obfs=over-tls' : ''}${n.host ? ', obfs-host=' + n.host : ''}${n.path ? ', obfs-uri=' + n.path : ''}${n.network === 'ws' ? ', obfs=ws' : ''}`;
    case 'trojan':
      return `trojan=${n.server}:${n.port}, password=${pwd}, tag=${tag}${n.sni ? ', tls-host=' + n.sni : ''}`;
    case 'vless':
      return `vless=${n.server}:${n.port}, method=none, password=${pwd}, tag=${tag}${n.tls && n.tls !== 'none' ? ', obfs=over-tls' : ''}${n.host ? ', obfs-host=' + n.host : ''}${n.path ? ', obfs-uri=' + n.path : ''}`;
    case 'http':
      return `http=${n.server}:${n.port}${n.username ? ', username=' + n.username : ''}${pwd ? ', password=' + pwd : ''}, tag=${tag}`;
    case 'socks5':
      return `socks5=${n.server}:${n.port}, tag=${tag}`;
    case 'hysteria':
    case 'hysteria2':
      return `hysteria=${n.server}:${n.port}, auth=${pwd}, tag=${tag}${n.sni ? ', tls-host=' + n.sni : ''}`;
    case 'anytls':
      // anytls → Trojan（QX 无原生 anytls 支持）
      return `trojan=${n.server}:${n.port}, password=${pwd}, tag=${tag}${n.sni ? ', tls-host=' + n.sni : ''}`;
  }
}

// 节点 → 原始协议链接（Shadowrocket 用）
function formatNodeRawUri(n) {
  // 对于已有原始链接的节点，直接返回；否则构造
  // 简化：返回原始订阅中的链接格式
  // 实际中需要从原始订阅内容中保留
  return `# ${n.rawName || n.name}`;
}

// ═══════════════════════════════════════════════════════════
//  规则 → 各格式字符串
// ═══════════════════════════════════════════════════════════

function formatRuleSurge(ruleLine) {
  const parts = ruleLine.split(',');
  let [type, value, ...rest] = parts;
  type = type.trim().toUpperCase();

  // 提取 no-resolve（Clash 格式: TYPE,value,no-resolve,policy → Surge: TYPE,value,policy,no-resolve）
  let noResolve = false;
  rest = rest.filter(r => {
    if (r.trim() === 'no-resolve') { noResolve = true; return false; }
    return true;
  });

  const typeMap = {
    'DOMAIN-SUFFIX': 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD': 'DOMAIN-KEYWORD',
    'DOMAIN': 'DOMAIN', 'IP-CIDR': 'IP-CIDR', 'IP-CIDR6': 'IP-CIDR6',
    'GEOIP': 'GEOIP', 'MATCH': 'FINAL', 'RULE-SET': 'RULE-SET',
    'DST-PORT': 'DST-PORT', 'SRC-PORT': 'SRC-PORT',
    'PROCESS-NAME': 'PROCESS-NAME', 'URL-REGEX': 'URL-REGEX',
    'AND': 'AND', 'OR': 'OR', 'NOT': 'NOT',
  };
  const surgeType = typeMap[type] || type;
  const result = `${surgeType},${value},${rest.join(',')}`;
  return noResolve ? result + ',no-resolve' : result;
}

function formatRuleQuanX(ruleLine) {
  const parts = ruleLine.split(',');
  let [type, value, ...rest] = parts;
  type = type.trim().toUpperCase();

  // Quantumult X 规则类型映射
  const typeMap = {
    'DOMAIN-SUFFIX': 'host-suffix',
    'DOMAIN-KEYWORD': 'host-keyword',
    'DOMAIN': 'host',
    'IP-CIDR': 'ip-cidr',
    'IP-CIDR6': 'ip6-cidr',
    'GEOIP': 'geoip',
    'MATCH': 'final',
    'USER-AGENT': 'user-agent',
  };
  const qxType = typeMap[type] || type.toLowerCase();
  
  // QX 格式: type, value, policy
  let policy = rest[rest.length - 1] || 'Proxy';
  // 去掉 no-resolve
  rest = rest.filter(r => r !== 'no-resolve');
  if (rest.length > 0 && rest[rest.length - 1]) policy = rest[rest.length - 1];
  
  return `${qxType}, ${value}, ${policy}`;
}

// ═══════════════════════════════════════════════════════════
//  完整配置构建
// ═══════════════════════════════════════════════════════════

function buildConfigSurge(nodes, proxyGroups, ruleData) {
  const lines = [];
  
  // [Proxy]
  lines.push('[Proxy]');
  for (const n of nodes) lines.push(formatNodeSurge(n));
  
  // [Proxy Group]
  lines.push('', '[Proxy Group]');
  const regionSet = new Map();
  for (const n of nodes) {
    if (n.region && !regionSet.has(n.region))
      regionSet.set(n.region, n.flag || '');
  }
  
  // 自动选择组
  const allNames = nodes.map(n => n.rawName || n.name);
  lines.push(`Proxy = select, ${allNames.join(', ')}, DIRECT`);
  lines.push(`Auto = url-test, ${allNames.join(', ')}, url=http://www.gstatic.com/generate_204, interval=300`);
  
  // 区域组
  for (const [region, flag] of regionSet) {
    const regionNodes = nodes.filter(n => n.region === region);
    const names = regionNodes.map(n => n.rawName || n.name);
    lines.push(`${flag}${region} = url-test, ${names.join(', ')}, url=http://www.gstatic.com/generate_204, interval=300`);
  }
  
  // 目标策略组
  const targetGroups = [
    ['DIRECT', '🎯 全球直连', 'Proxy'],
    ['REJECT', '🛑 广告拦截', 'DIRECT'],
    ['Proxy', '🐟 漏网之鱼', 'DIRECT'],
    ['Proxy', '📲 电报消息', 'DIRECT'],
    ['Proxy', '🌍 国外媒体', 'DIRECT'],
  ];
  for (const [def, name, alt] of targetGroups) {
    const regionEntries = [];
    for (const [region, flag] of regionSet) {
      regionEntries.push(`${flag}${region}`);
    }
    lines.push(`${name} = select, ${def === 'Proxy' ? 'Proxy, ' : ''}${def === 'REJECT' ? '' : 'Proxy, '}Auto, ${regionEntries.join(', ')}, ${alt}`);
  }
  
  // [Rule]
  lines.push('', '[Rule]');
  for (const r of ruleData) lines.push(formatRuleSurge(r.line));
  
  return lines.join('\n');
}

function buildConfigQuanX(nodes, proxyGroups, ruleData) {
  const lines = [];
  
  // [server_local]
  lines.push('[server_local]');
  for (const n of nodes) lines.push(formatNodeQuanX(n));
  
  // [policy]
  lines.push('', '[policy]');
  const allNames = nodes.map(n => (n.rawName || n.name).replace(/[,=]/g, '_'));
  lines.push(`static=Proxy, ${allNames.join(', ')}, img-url=system`);
  lines.push(`available=Auto, ${allNames.join(', ')}, url=http://www.gstatic.com/generate_204, interval=300`);
  
  const regionSet = new Map();
  for (const n of nodes) {
    if (n.region && !regionSet.has(n.region))
      regionSet.set(n.region, n.flag || '');
  }
  for (const [region, flag] of regionSet) {
    const rNodes = nodes.filter(n => n.region === region);
    const names = rNodes.map(n => (n.rawName || n.name).replace(/[,=]/g, '_'));
    lines.push(`available=${flag}${region}, ${names.join(', ')}, url=http://www.gstatic.com/generate_204, interval=300`);
  }
  
  lines.push('static=🎯 全球直连, DIRECT, Proxy');
  lines.push('static=🛑 广告拦截, REJECT, DIRECT');
  lines.push('static=🐟 漏网之鱼, Proxy, Auto, DIRECT');
  
  // [filter_local]
  lines.push('', '[filter_local]');
  for (const r of ruleData) lines.push(formatRuleQuanX(r.line));
  
  return lines.join('\n');
}

// ═══════════════════════════════════════════════════════════
//  主入口
// ═══════════════════════════════════════════════════════════

function buildConfigForTarget(target, nodes, ruleData, host, rawSubUrl) {
  // Clash 系走原有 YAML 构建器
  if (target === 'clash' || target === 'stash' || target === 'clashr') {
    // 由 server.js 的 buildProviderConfig / buildInlineConfig 处理
    return null;
  }

  // Surge
  if (target === 'surge' || target === 'surfboard') {
    return buildConfigSurge(nodes, [], ruleData);
  }

  // Quantumult X
  if (target === 'quanx' || target === 'quantumult' || target === 'quan') {
    return buildConfigQuanX(nodes, [], ruleData);
  }

  // Loon（与 Surge 格式兼容）
  if (target === 'loon') {
    return buildConfigSurge(nodes, [], ruleData);
  }

  return null;
}

module.exports = { buildConfigForTarget };
