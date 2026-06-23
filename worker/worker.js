/**
 * ProxyPress Worker v2: 全量规则订阅转换
 * 节点从订阅拉取，规则从 GitHub ACL4SSR 拉取，本地组装
 */

// ACL4SSR 规则集（组 → GitHub 规则文件 URL）
const RULESETS = {
  '🎯 全球直连': [
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/UnBan.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/GoogleCN.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Download.list',
  ],
  '🛑 广告拦截': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list'],
  '🍃 应用净化': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list'],
  '📢 谷歌FCM': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/GoogleFCM.list'],
  'Ⓜ️ 微软Bing': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Bing.list'],
  'Ⓜ️ 微软云盘': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/OneDrive.list'],
  'Ⓜ️ 微软服务': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Microsoft.list'],
  '🍎 苹果服务': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Apple.list'],
  '📲 电报消息': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Telegram.list'],
  '📹 油管视频': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YouTube.list'],
  '🎥 奈飞视频': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list'],
  '📺 哔哩哔哩': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Bilibili.list','https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/BilibiliHMT.list'],
  '🌍 国外媒体': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ProxyMedia.list'],
  '🌏 国内媒体': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaMedia.list'],
  '🎶 网易音乐': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/NetEaseMusic.list'],
  '💬 Ai平台': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list','https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list'],
  '🎮 游戏平台': ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Steam.list','https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Epic.list','https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Sony.list','https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Nintendo.list'],
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const p = url.pathname;

    if (p === '/health') return new Response('OK');

    if (p === '/sub') {
      const rawUrl = url.searchParams.get('url');
      if (!rawUrl) return new Response('Missing url param', { status: 400 });

      try {
        const decodedUrl = decodeURIComponent(rawUrl);

        // 1. 拉取订阅并解析节点
        const subResp = await fetch(decodedUrl, {
          headers: { 'User-Agent': 'ProxyPress/2.0', 'Accept': '*/*' }
        });
        let body = await subResp.text();

        // base64 解码
        if (/^[A-Za-z0-9+/=\s]+$/.test(body.trim()) && body.length > 50) {
          try {
            const bin = atob(body.replace(/\s/g, ''));
            if (bin.includes('://')) body = bin;
          } catch (_) {}
        }

        const lines = body.split('\n').filter(l => l.includes('://'));
        const proxies = [];
        for (const line of lines) {
          const node = parseNode(line.trim());
          if (node) proxies.push(node);
        }
        if (proxies.length === 0) {
          return new Response('No nodes found', { status: 400 });
        }

        // 2. 并行拉取所有规则文件
        const rulePromises = [];
        for (const [group, urls] of Object.entries(RULESETS)) {
          for (const ruleUrl of urls) {
            rulePromises.push(
              fetch(ruleUrl, { headers: { 'User-Agent': 'ProxyPress/2.0' } })
                .then(r => r.text())
                .then(t => ({ group, text: t }))
                .catch(() => null)
            );
          }
        }
        const ruleResults = (await Promise.all(rulePromises)).filter(Boolean);

        // 3. 解析规则
        const rules = [{ type: 'GEOIP', value: 'CN', target: '🎯 全球直连' }];
        for (const { group, text } of ruleResults) {
          for (const line of text.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            if (trimmed.includes(',')) {
              rules.push({ type: 'inline', value: trimmed, target: group });
            } else {
              // IP-CIDR or DOMAIN without type
              rules.push({ type: 'inline', value: trimmed, target: group });
            }
          }
        }
        rules.push({ type: 'MATCH', value: '', target: '🐟 漏网之鱼' });

        // 4. 组装配置
        const yaml = buildFullConfig(proxies, rules);

        return new Response(yaml, {
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=300'
          }
        });
      } catch (e) {
        return new Response(`Error: ${e.message}`, { status: 502 });
      }
    }

    return new Response('ProxyPress Worker v2', { status: 404 });
  }
};

function parseNode(uri) {
  try {
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
  } catch (_) { return null; }
}

function buildFullConfig(proxies, rules) {
  const names = proxies.map(p => p.name);
  const lines = [
    'port: 7890', 'socks-port: 7891', 'allow-lan: true', 'mode: Rule', 'log-level: info', '',
    'proxies:',
  ];
  for (const p of proxies) {
    lines.push(`  - {name: ${JSON.stringify(p.name)}, server: ${p.server}, port: ${p.port}, type: ${p.type}, password: ${JSON.stringify(p.password)}, fingerprint: ${p.fingerprint}, sni: ${p.sni}, skip-cert-verify: ${p['skip-cert-verify']}, udp: ${p.udp}}`);
  }

  // proxy-groups
  lines.push('', 'proxy-groups:');
  // 主选择器
  lines.push('  - name: 🚀 节点选择', '    type: select', '    proxies:');
  lines.push('      - ♻️ 自动选择');
  for (const n of names) lines.push(`      - ${n}`);
  lines.push('      - DIRECT');
  // 自动测速
  lines.push('  - name: ♻️ 自动选择', '    type: url-test', '    proxies:');
  for (const n of names) lines.push(`      - ${n}`);
  lines.push('    url: http://www.gstatic.com/generate_204', '    interval: 300');
  // 策略组
  const groups = [...new Set(rules.filter(r => r.target).map(r => r.target))];
  for (const g of groups) {
    if (g === '🎯 全球直连') {
      lines.push(`  - name: ${g}`, '    type: select', '    proxies:', '      - DIRECT', '      - 🚀 节点选择');
    } else if (g === '🛑 广告拦截' || g === '🍃 应用净化') {
      lines.push(`  - name: ${g}`, '    type: select', '    proxies:', '      - REJECT', '      - DIRECT');
    } else if (g === '🐟 漏网之鱼') {
      lines.push(`  - name: ${g}`, '    type: select', '    proxies:', '      - 🚀 节点选择', '      - DIRECT');
    } else {
      lines.push(`  - name: ${g}`, '    type: select', '    proxies:', '      - 🚀 节点选择', '      - ♻️ 自动选择', '      - DIRECT');
    }
  }

  // rules
  lines.push('', 'rules:');
  for (const r of rules) {
    if (r.type === 'GEOIP') {
      lines.push(`  - GEOIP,${r.value},${r.target}`);
    } else if (r.type === 'MATCH') {
      lines.push(`  - MATCH,${r.target}`);
    } else {
      lines.push(`  - ${r.value}`);
    }
  }

  return lines.join('\n');
}
