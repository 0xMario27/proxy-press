/**
 * Cloudflare Worker: sub-smart 精简版
 * - 拉取订阅 → 检测 base64 → 解码 → 转发给公共 subconverter
 * - 部署: npx wrangler deploy
 */

const SUBCONVERTER = 'https://api.wcc.best';

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    // /health
    if (path === '/health') return new Response('OK');

    // /sub - 订阅转换代理
    if (path === '/sub') {
      const targetUrl = `${SUBCONVERTER}/sub?${url.searchParams.toString()}`;

      try {
        // 先尝试直接转发（带浏览器 UA 避免被拦截）
        let resp = await fetch(targetUrl, {
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; ProxyPress/1.0)',
            'Accept': '*/*'
          }
        });
        let text = await resp.text();

        // 如果 subconverter 无法解析，尝试自己拉取订阅并解码 base64
        if (text.includes('No nodes were found') || text.includes('Invalid')) {
          const rawUrl = url.searchParams.get('url');
          if (rawUrl) {
            const decodedUrl = decodeURIComponent(rawUrl);
            const subResp = await fetch(decodedUrl, {
              headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ProxyPress/1.0)', 'Accept': '*/*' }
            });
            const rawBody = await subResp.text();

            // 检查是否被拦截
            if (rawBody.includes('blocked') || rawBody.includes('Sorry')) {
              return new Response('Backend blocked. Try again later.', { status: 502 });
            }

            // 尝试 base64 解码
            let decoded = rawBody;
            if (/^[A-Za-z0-9+/=\s]+$/.test(rawBody.trim()) && rawBody.length > 50) {
              try {
                const bin = atob(rawBody.replace(/\s/g, ''));
                if (bin.includes('://')) decoded = bin;
              } catch (_) {}
            }

            // 用 data URI 重新请求 subconverter
            const dataUri = 'data:text/plain;base64,' + btoa(unescape(encodeURIComponent(decoded)));
            url.searchParams.set('url', dataUri);
            const retryUrl = `${SUBCONVERTER}/sub?${url.searchParams.toString()}`;
            resp = await fetch(retryUrl);
            text = await resp.text();
          }
        }

        return new Response(text, {
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Access-Control-Allow-Origin': '*'
          }
        });
      } catch (e) {
        return new Response(`Error: ${e.message}`, { status: 502 });
      }
    }

    return new Response('Not Found', { status: 404 });
  }
};
