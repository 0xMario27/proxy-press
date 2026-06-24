/**
 * sub-smart-js — 纯 JS 订阅转换服务器（Node.js HTTP 层）
 * 
 * 业务逻辑来自 ./shared.js，解析器来自 ./parser.js
 * 
 * 端点:
 *   /sub?mode=provider|inline&url=...&config=...
 *   /list?url=...     — proxy-provider 节点列表
 *   /rules/<hash>.yaml — rule-provider 内容
 *   /fetch?url=...     — 订阅代理
 *   /version /health
 */

'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

// ─── 业务逻辑 ───
const { parseSubscription } = require('./parser.js');
const {
  RULE_STORE, BASE_RULES_URL, REGION_MAP,
  isBase64, base64Decode,
  parseRulesets,
  processRuleText,
  detectRegion, enhanceNodes,
  formatNodeCompact, formatNodeBlockYaml,
  buildProviderConfig, buildInlineConfig,
  buildRuleProviders, buildRuleRefs,
  buildGroupsWithProvider, buildGroupsInline,
  addTargetGroups
} = require('./shared.js');

// ═══════════════════════════════════════════════════════════
//  平台常量（Node.js 专用）
// ═══════════════════════════════════════════════════════════

const CONFIG_DIR = path.join(__dirname, 'Clash', 'config');
const PORT = parseInt(process.env.PORT || '25600');
const HOST_IP = process.env.HOST_IP || 'localhost';

// ═══════════════════════════════════════════════════════════
//  网络工具（Node.js http/https 实现）
// ═══════════════════════════════════════════════════════════

function fetchText(fetchUrl, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const u = new URL(fetchUrl);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.get(u, { timeout, headers: { 'User-Agent': 'sub-smart-js/1.0', 'Accept': '*/*' } }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchText(res.headers.location, timeout).then(resolve, reject);
      }
      if (res.statusCode >= 400) {
        req.destroy();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve(body));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

// ═══════════════════════════════════════════════════════════
//  规则获取（平台相关：Node.js fs + http + 本地 Clash/）
// ═══════════════════════════════════════════════════════════

function resolveLocalRule(ruleUrl) {
  const m = ruleUrl.match(/Clash\/(.+)/);
  if (m) {
    const localPath = path.join(__dirname, 'Clash', m[1]);
    if (fs.existsSync(localPath)) return localPath;
  }
  const basename = path.basename(ruleUrl);
  const altPath = path.join(__dirname, 'Clash', basename);
  if (fs.existsSync(altPath)) return altPath;
  const rsPath = path.join(__dirname, 'Clash', 'Ruleset', basename);
  if (fs.existsSync(rsPath)) return rsPath;
  return null;
}

async function fetchRulesFromConfig(rulesets) {
  const rules = [];
  const promises = [];
  for (const { group, url: ruleUrl } of rulesets) {
    const localRule = resolveLocalRule(ruleUrl);
    if (localRule) {
      promises.push(
        Promise.resolve().then(() => {
          const text = fs.readFileSync(localRule, 'utf-8');
          processRuleText(text, group, rules);
        }).catch(() => {})
      );
    } else {
      const fullUrl = ruleUrl.startsWith('http') ? ruleUrl : (BASE_RULES_URL + ruleUrl.replace(/^Clash\//, ''));
      promises.push(
        fetchText(fullUrl, 10000).then(text => {
          processRuleText(text, group, rules);
        }).catch(() => {})
      );
    }
  }
  await Promise.all(promises);
  rules.push({ group: '🎯 全球直连', line: 'GEOIP,CN,🎯 全球直连' });
  rules.push({ group: '🐟 漏网之鱼', line: 'MATCH,🐟 漏网之鱼' });
  return rules;
}

// ═══════════════════════════════════════════════════════════
//  订阅获取
// ═══════════════════════════════════════════════════════════

async function fetchAndParseSub(subUrl) {
  if (!/^https?:\/\//.test(subUrl)) {
    let body = decodeURIComponent(subUrl);
    if (isBase64(body) && !body.includes('://')) {
      const decoded = base64Decode(body);
      if (decoded.includes('://') || decoded.includes(' = ')) body = decoded;
    }
    return parseSubscription(body);
  }
  let body = await fetchText(subUrl);
  if (isBase64(body) && !body.includes('://')) {
    const decoded = base64Decode(body);
    if (decoded.includes('://')) body = decoded;
  }
  return parseSubscription(body);
}

// ═══════════════════════════════════════════════════════════
//  HTTP 请求处理
// ═══════════════════════════════════════════════════════════

function parseQuery(reqUrl) {
  const u = new URL(reqUrl, 'http://localhost');
  return { pathname: u.pathname, params: Object.fromEntries(u.searchParams) };
}

function respond(res, code, body, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(code, {
    'Content-Type': contentType,
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'public, max-age=300'
  });
  res.end(body);
}

async function handleRequest(req, res) {
  const { pathname, params } = parseQuery(req.url);

  try {
    if (pathname === '/health') return respond(res, 200, 'OK');
    if (pathname === '/version') return respond(res, 200, 'sub-smart-js v1.0');

    // /fetch - 订阅代理
    if (pathname === '/fetch') {
      const fetchUrl = params.url;
      if (!fetchUrl) return respond(res, 400, 'Missing url param');
      const body = await fetchText(fetchUrl);
      return respond(res, 200, body);
    }

    // /rules/<hash>.yaml - 规则文件
    if (pathname.startsWith('/rules/') && pathname.endsWith('.yaml')) {
      const hash = pathname.split('/rules/')[1].replace('.yaml', '');
      const content = RULE_STORE.get(hash);
      if (content) {
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=86400'
        });
        return res.end(content);
      }
      return respond(res, 404, 'Rules not found');
    }

    // /list - 节点列表
    if (pathname === '/list') {
      const listUrl = params.url;
      if (!listUrl) return respond(res, 400, 'Missing url param');
      const nodes = await fetchAndParseSub(listUrl);
      enhanceNodes(nodes);
      const yaml = ['proxies:'];
      for (const n of nodes) yaml.push(formatNodeCompact(n));
      return respond(res, 200, yaml.join('\n'));
    }

    // /sub - 订阅转换
    if (pathname === '/sub') {
      const subUrl = params.url;
      if (!subUrl) return respond(res, 400, 'Missing url param');

      const mode = params.mode || 'provider';
      const configFile = params.config || '';

      const nodes = await fetchAndParseSub(subUrl);
      if (!nodes.length) return respond(res, 400, 'No nodes found in subscription');
      enhanceNodes(nodes);

      let ruleData = [];
      if (configFile) {
        let configPath = path.join(CONFIG_DIR, path.basename(configFile));
        const relPath = path.join(__dirname, configFile.replace(/^\//, ''));
        if (fs.existsSync(relPath)) configPath = relPath;

        let iniContent = '';
        if (fs.existsSync(configPath)) {
          console.log('[config] Loading local config:', configPath);
          iniContent = fs.readFileSync(configPath, 'utf-8');
        } else if (configFile.startsWith('http')) {
          console.log('[config] Fetching remote config:', configFile);
          iniContent = await fetchText(configFile).catch(() => '');
        } else {
          console.log('[config] Config not found:', configPath, '(tried:', relPath, ')');
        }
        if (iniContent) {
          const rulesets = parseRulesets(iniContent);
          console.log('[config] Parsed', rulesets.length, 'rulesets');
          try {
            ruleData = await Promise.race([
              fetchRulesFromConfig(rulesets),
              new Promise((_, rej) => setTimeout(() => rej(new Error('rules fetch timeout')), 20000))
            ]);
            console.log('[config] Fetched', ruleData.length, 'rules');
          } catch (e) {
            console.error('[warn] Rule fetch failed:', e.message);
            ruleData = [];
          }
        }
      }

      const proto = req.headers['x-forwarded-proto'] || 'http';
      const host = `${proto}://${req.headers.host || `${HOST_IP}:${PORT}`}`;
      const result = (mode === 'provider')
        ? buildProviderConfig(nodes, ruleData, host, subUrl)
        : buildInlineConfig(nodes, ruleData, host);

      return respond(res, 200, result);
    }

    respond(res, 404, 'Not Found');
  } catch (e) {
    console.error('[error]', e.message);
    respond(res, 500, `Error: ${e.message}`);
  }
}

// ═══════════════════════════════════════════════════════════
//  启动
// ═══════════════════════════════════════════════════════════

const server = http.createServer(handleRequest);
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[sub-smart-js] listening on :${PORT}`);
  console.log(`[sub-smart-js] GET /sub?mode=provider|inline&url=...&config=...`);
  console.log(`[sub-smart-js] GET /list?url=... /rules/<hash>.yaml /fetch?url=...`);
  console.log(`[sub-smart-js] Config dir: ${CONFIG_DIR}`);
});
