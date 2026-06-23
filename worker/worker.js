/**
 * ProxyPress Worker: 智能订阅转换代理
 * 策略：优先用公共 subconverter，失败时自建最小配置
 */
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const p = url.pathname;

    if (p === '/health') return new Response('OK');

    if (p === '/sub') {
      const rawUrl = url.searchParams.get('url');
      if (!rawUrl) return new Response('Missing url param', { status: 400 });

      try {
        // 方案 A：先试公共 subconverter（干净请求头）
        const publicBackends = [
          'https://api.wcc.best',
        ];

        for (const backend of publicBackends) {
          try {
            const target = `${backend}/sub?${url.searchParams.toString()}`;
            const resp = await fetch(target, {
              headers: {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Accept': 'text/plain,*/*'
              }
            });
            const text = await resp.text();

            // 检查是否真正的转换结果
            if (text.includes('proxies:') || text.includes('Proxy:')) {
              return new Response(text, {
                headers: {
                  'Content-Type': 'text/plain; charset=utf-8',
                  'Access-Control-Allow-Origin': '*'
                }
              });
            }

            // 被拦截的不是有效结果
            if (text.includes('blocked') || text.includes('Sorry') || text.includes('cloudflare')) {
              continue;
            }
          } catch (_) {
            continue;
          }
        }

        // 方案 B：自建最小配置
        const decodedUrl = decodeURIComponent(rawUrl);
        const subResp = await fetch(decodedUrl, {
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ProxyPress/1.0)', 'Accept': '*/*' }
        });
        const rawBody = await subResp.text();

        let body = rawBody;
        if (/^[A-Za-z0-9+/=\s]+$/.test(rawBody.trim()) && rawBody.length > 50) {
          try {
            const bin = atob(rawBody.replace(/\s/g, ''));
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
          return new Response('No nodes found. Subscription may be empty.', { status: 400 });
        }

        const yaml = buildConfig(proxies);
        return new Response(yaml, {
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Access-Control-Allow-Origin': '*'
          }
        });

      } catch (e) {
        return new Response(`Error: ${e.message}`, { status: 502 });
      }
    }

    return new Response('ProxyPress Worker', { status: 404 });
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

function buildConfig(proxies) {
  const names = proxies.map(p => p.name);
  const lines = [
    'port: 7890', 'socks-port: 7891', 'allow-lan: true', 'mode: Rule', 'log-level: info', '',
    'proxies:',
  ];
  for (const p of proxies) {
    lines.push(`  - {name: ${JSON.stringify(p.name)}, server: ${p.server}, port: ${p.port}, type: ${p.type}, password: ${JSON.stringify(p.password)}, fingerprint: ${p.fingerprint}, sni: ${p.sni}, skip-cert-verify: ${p['skip-cert-verify']}, udp: ${p.udp}}`);
  }
  lines.push('', 'proxy-groups:');
  lines.push('  - name: 🚀 Proxy', '    type: select', '    proxies:');
  for (const n of names) lines.push(`      - ${n}`);
  lines.push('      - DIRECT');
  lines.push('', '  - name: 🎯 Auto', '    type: url-test', '    proxies:');
  for (const n of names) lines.push(`      - ${n}`);
  lines.push('    url: http://www.gstatic.com/generate_204', '    interval: 300');
  lines.push('', 'rules:', '  - MATCH,🚀 Proxy');
  return lines.join('\n');
}
