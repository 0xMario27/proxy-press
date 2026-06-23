/**
 * ProxyPress Worker v3: 完整 proxy-provider + rule-provider 支持
 */
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const p = url.pathname;

    if (p === '/health') return new Response('OK');

    // /list — 仅返回节点列表（proxy-provider 用）
    if (p === '/list') {
      const rawUrl = url.searchParams.get('url');
      if (!rawUrl) return new Response('Missing url', { status: 400 });
      const nodes = await fetchNodes(rawUrl);
      if (!nodes.length) return new Response('No nodes', { status: 400 });
      const yaml = ['proxies:'];
      for (const n of nodes) yaml.push(`  - {name: ${JSON.stringify(n.name)}, server: ${n.server}, port: ${n.port}, type: ${n.type}, password: ${JSON.stringify(n.password)}, fingerprint: ${n.fingerprint}, sni: ${n.sni}, skip-cert-verify: ${n['skip-cert-verify']}, udp: ${n.udp}}`);
      return respond(yaml.join('\n'), 300);
    }

    // /rules/:hash — 规则文件端点
    if (p.startsWith('/rules/')) {
      const hash = p.split('/rules/')[1].replace('.yaml', '');
      const cached = RULE_STORE.get(hash);
      return cached ? respond(cached, 86400) : new Response('Not found', { status: 404 });
    }

    // /sub — 主转换端点
    if (p === '/sub') {
      const rawUrl = url.searchParams.get('url');
      const mode = url.searchParams.get('mode') || 'inline';
      if (!rawUrl) return new Response('Missing url param', { status: 400 });

      try {
        const nodes = await fetchNodes(rawUrl);
        if (!nodes.length) return new Response('No nodes found', { status: 400 });

        // 拉取规则
        const ruleData = await fetchRules();

        let result;
        if (mode === 'provider') {
          result = buildProviderConfig(nodes, ruleData, url.origin, rawUrl);
        } else {
          result = buildInlineConfig(nodes, ruleData);
        }

        return respond(result, 300);
      } catch (e) {
        return new Response(`Error: ${e.message}`, { status: 502 });
      }
    }

    return new Response('ProxyPress Worker v3', { status: 404 });
  }
};

// ─── 数据 ───

const RULE_STORE = new Map();

const RULESETS = {
  '🎯 全球直连': ['LocalAreaNetwork.list','UnBan.list','GoogleCN.list','ChinaDomain.list','ChinaCompanyIp.list','Download.list'],
  '🛑 广告拦截': ['BanAD.list'],
  '🍃 应用净化': ['BanProgramAD.list'],
  '📢 谷歌FCM': ['Ruleset/GoogleFCM.list'],
  'Ⓜ️ 微软Bing': ['Bing.list'],
  'Ⓜ️ 微软云盘': ['OneDrive.list'],
  'Ⓜ️ 微软服务': ['Microsoft.list'],
  '🍎 苹果服务': ['Apple.list'],
  '📲 电报消息': ['Telegram.list'],
  '📹 油管视频': ['Ruleset/YouTube.list'],
  '🎥 奈飞视频': ['Ruleset/Netflix.list'],
  '📺 哔哩哔哩': ['Ruleset/Bilibili.list','Ruleset/BilibiliHMT.list'],
  '🌍 国外媒体': ['ProxyMedia.list'],
  '🌏 国内媒体': ['ChinaMedia.list'],
  '🎶 网易音乐': ['Ruleset/NetEaseMusic.list'],
  '💬 Ai平台': ['Ruleset/AI.list','Ruleset/OpenAi.list'],
  '🎮 游戏平台': ['Ruleset/Steam.list','Ruleset/Epic.list','Ruleset/Sony.list','Ruleset/Nintendo.list'],
};

const BASE = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/';

// ─── 网络 ───

async function fetchNodes(rawUrl) {
  const decodedUrl = decodeURIComponent(rawUrl);
  const resp = await fetch(decodedUrl, {
    headers: { 'User-Agent': 'ProxyPress/3.0', 'Accept': '*/*' }
  });
  let body = await resp.text();
  if (/^[A-Za-z0-9+/=\s]+$/.test(body.trim()) && body.length > 50) {
    try { const bin = atob(body.replace(/\s/g, '')); if (bin.includes('://')) body = bin; } catch (_) {}
  }
  const nodes = [];
  for (const line of body.split('\n')) {
    const n = parseNode(line.trim());
    if (n) nodes.push(n);
  }
  return nodes;
}

async function fetchRules() {
  const rules = [];
  const promises = [];
  for (const [group, files] of Object.entries(RULESETS)) {
    for (const f of files) {
      promises.push(
        fetch(BASE + f, { headers: { 'User-Agent': 'ProxyPress/3.0' } })
          .then(r => r.text())
          .then(t => {
            for (const line of t.split('\n')) {
              const s = line.trim();
              if (!s || s.startsWith('#')) continue;
              rules.push({ group, line: s.includes(',') ? s : s });
            }
          })
          .catch(() => {})
      );
    }
  }
  await Promise.all(promises);
  rules.push({ group: '🎯 全球直连', line: 'GEOIP,CN,🎯 全球直连' });
  rules.push({ group: '🐟 漏网之鱼', line: 'MATCH,🐟 漏网之鱼' });
  return rules;
}

function parseNode(uri) {
  const m = uri.match(/^(\w+):\/\/([^@]+)@([^:]+):(\d+)\/?(?:\?(.*))?#?(.*)$/);
  if (!m) return null;
  const [, proto, password, server, port, queryStr, name] = m;
  const params = new URLSearchParams(queryStr || '');
  return {
    name: decodeURIComponent(name || `${server}:${port}`),
    server, port: parseInt(port),
    type: proto, password,
    fingerprint: params.get('fp') || 'chrome',
    sni: params.get('sni') || server,
    'skip-cert-verify': params.get('insecure') === '1' || false,
    udp: params.get('udp') === '1' || false
  };
}

// ─── 构建配置 ───

function buildInlineConfig(nodes, rules) {
  const names = nodes.map(n => n.name);
  const lines = [
    'port: 7890', 'socks-port: 7891', 'allow-lan: true', 'mode: Rule', 'log-level: info', '',
    'proxies:'
  ];
  for (const n of nodes) {
    lines.push(`  - {name: ${JSON.stringify(n.name)}, server: ${n.server}, port: ${n.port}, type: ${n.type}, password: ${JSON.stringify(n.password)}, fingerprint: ${n.fingerprint}, sni: ${n.sni}, skip-cert-verify: ${n['skip-cert-verify']}, udp: ${n.udp}}`);
  }
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
  ];

  // Rule-providers
  lines.push('rule-providers:');
  const ruleGroups = {};
  for (const r of rules) {
    if (!ruleGroups[r.group]) ruleGroups[r.group] = [];
    ruleGroups[r.group].push(r.line);
  }

  const ruleRefs = [];
  let idx = 0;
  for (const [group, rlines] of Object.entries(ruleGroups)) {
    const content = rlines.join('\n');
    const hash = simpleHash(content);
    const name = sanitize(group);
    RULE_STORE.set(hash, rlines.join('\n'));

    lines.push(`  ${name}:`);
    lines.push('    type: http');
    lines.push('    behavior: classical');
    lines.push(`    path: ./rulesets/${name}.yaml`);
    lines.push(`    url: ${host}/rules/${hash}.yaml`);
    lines.push('    interval: 86400');

    ruleRefs.push(`  - RULE-SET,${name},${group}`);
  }

  lines.push('');

  // proxy-groups with use:
  lines.push(...buildGroupsWithProvider(names));
  lines.push('', 'rules:');
  lines.push(...ruleRefs);

  return lines.join('\n');
}

function buildGroups(names) {
  const lines = ['', 'proxy-groups:'];
  lines.push('  - name: 🚀 节点选择', '    type: select', '    proxies:');
  lines.push('      - ♻️ 自动选择');
  for (const n of names) lines.push(`      - ${n}`);
  lines.push('      - DIRECT');

  lines.push('  - name: ♻️ 自动选择', '    type: url-test', '    proxies:');
  for (const n of names) lines.push(`      - ${n}`);
  lines.push('    url: http://www.gstatic.com/generate_204', '    interval: 300');

  const targets = [...new Set(['🎯 全球直连','🛑 广告拦截','🍃 应用净化','🐟 漏网之鱼','📲 电报消息','📹 油管视频','🎥 奈飞视频','📺 哔哩哔哩','🌍 国外媒体','🌏 国内媒体','📢 谷歌FCM','Ⓜ️ 微软Bing','Ⓜ️ 微软云盘','Ⓜ️ 微软服务','🍎 苹果服务','🎶 网易音乐','💬 Ai平台','🎮 游戏平台'])];
  for (const t of targets) {
    if (t === '🎯 全球直连') {
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - DIRECT', '      - 🚀 节点选择');
    } else if (t === '🛑 广告拦截' || t === '🍃 应用净化') {
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - REJECT', '      - DIRECT');
    } else if (t === '🐟 漏网之鱼') {
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - 🚀 节点选择', '      - DIRECT');
    } else {
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - 🚀 节点选择', '      - ♻️ 自动选择', '      - DIRECT');
    }
  }
  return lines;
}

function buildGroupsWithProvider(names) {
  const lines = ['proxy-groups:'];
  lines.push('  - name: 🚀 节点选择', '    type: select', '    proxies:');
  lines.push('      - ♻️ 自动选择');
  for (const n of names) lines.push(`      - ${n}`);
  lines.push('      - DIRECT');

  lines.push('  - name: ♻️ 自动选择', '    type: url-test');
  lines.push('    use:', '      - provider');
  lines.push('    url: http://www.gstatic.com/generate_204', '    interval: 300');

  // 区域过滤组
  const regions = { '🇭🇰 香港节点': '香港', '🇨🇳 台湾节点': '台湾', '🇯🇵 日本节点': '日本', '🇺🇲 美国节点': '美国', '🇸🇬 狮城节点': '新加坡', '🇰🇷 韩国节点': '韩国' };
  for (const [name, filter] of Object.entries(regions)) {
    lines.push(`  - name: ${name}`, '    type: url-test');
    lines.push('    use:', '      - provider');
    lines.push(`    filter: "${filter}"`);
    lines.push('    url: http://www.gstatic.com/generate_204', '    interval: 300');
  }

  const targets = [...new Set(['🎯 全球直连','🛑 广告拦截','🍃 应用净化','🐟 漏网之鱼','📲 电报消息','📹 油管视频','🎥 奈飞视频','📺 哔哩哔哩','🌍 国外媒体','🌏 国内媒体','📢 谷歌FCM','Ⓜ️ 微软Bing','Ⓜ️ 微软云盘','Ⓜ️ 微软服务','🍎 苹果服务','🎶 网易音乐','💬 Ai平台','🎮 游戏平台'])];
  for (const t of targets) {
    if (t === '🎯 全球直连') {
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - DIRECT', '      - 🚀 节点选择');
    } else if (t === '🛑 广告拦截' || t === '🍃 应用净化') {
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - REJECT', '      - DIRECT');
    } else if (t === '🐟 漏网之鱼') {
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - 🚀 节点选择', '      - DIRECT', '      - ♻️ 自动选择');
    } else {
      lines.push(`  - name: ${t}`, '    type: select', '    proxies:', '      - 🚀 节点选择', '      - ♻️ 自动选择', '      - DIRECT');
    }
  }
  return lines;
}

function buildRules(rules) {
  const lines = ['', 'rules:'];
  for (const r of rules) lines.push(`  - ${r.line}`);
  return lines;
}

// ─── 工具 ───

function sanitize(s) {
  return s.replace(/[^\w\u4e00-\u9fff]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'other';
}

function simpleHash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h) + s.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h).toString(16).padStart(8, '0').slice(0, 8);
}

function respond(body, maxAge) {
  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': `public, max-age=${maxAge}`
    }
  });
}

function respond(body, maxAge) {
