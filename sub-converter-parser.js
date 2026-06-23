/**
 * sub-converter-parser.js
 * 
 * JS 版订阅链接解析器 —— 对标 C++ subconverter 的 subparser.cpp
 * 
 * 支持的协议:
 *   vmess:// | ss:// | ssr:// | trojan:// | vless:// 
 *   hysteria:// | hy:// | hysteria2:// | hy2:// | tuic:// | anytls://
 *   socks:// | http:// | https:// | clash YAML | surge conf
 * 
 * 解析入口:
 *   parseSubscription(content) → ProxyNode[]
 *   parseNode(uri)            → ProxyNode | null
 */

// ═══════════════════════════════════════════════════════════
//  类型定义
// ═══════════════════════════════════════════════════════════

/**
 * @typedef {Object} ProxyNode
 * @property {string} type     - ss | ssr | vmess | trojan | vless | hysteria | hysteria2 | tuic | anytls | socks5 | http | https | snell | wireguard
 * @property {string} name     - 节点名称 / remarks
 * @property {string} server   - 服务器地址
 * @property {number|string} port - 端口
 * @property {string} [password]
 * @property {string} [uuid]   - VMess/VLESS/TUIC UUID
 * @property {string} [cipher] - 加密方式 (ss/vmess)
 * @property {string} [network] - tcp|ws|grpc|h2|quic|xhttp
 * @property {string} [path]   - path / ws-path / grpc-service-name
 * @property {string} [host]   - ws host / sni
 * @property {string} [sni]
 * @property {string} [tls]    - tls|xtls|reality|none
 * @property {boolean} [skipCertVerify]
 * @property {boolean} [udp]
 * @property {object} [...]    - 所有其他协议特有字段
 */

// ═══════════════════════════════════════════════════════════
//  工具函数
// ═══════════════════════════════════════════════════════════

/**
 * URL-safe Base64 解码
 */
function urlSafeBase64Decode(str) {
  if (!str) return '';
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  // 补齐 padding
  while (str.length % 4) str += '=';
  try {
    return Buffer.from(str, 'base64').toString('utf-8');
  } catch {
    return str;
  }
}

function base64Decode(str) {
  try {
    return Buffer.from(str, 'base64').toString('utf-8');
  } catch {
    return str;
  }
}

/**
 * 从 URL query 中提取参数
 */
function getUrlArg(query, key) {
  if (!query) return '';
  const regex = new RegExp(`[?&]${encodeURIComponent(key)}=([^&]*)`);
  const m = query.match(regex);
  return m ? decodeURIComponent(m[1]) : '';
}

function parseQueryString(qs) {
  const params = {};
  if (!qs) return params;
  for (const part of qs.split('&')) {
    const [k, v] = part.split('=');
    if (k) params[k] = v ? decodeURIComponent(v) : '';
  }
  return params;
}

/**
 * 提取 #remarks 并从 URI 中移除
 */
function extractRemark(uri) {
  let remark = '';
  // 最后一个 # 作为 remarks
  const hashPos = uri.lastIndexOf('#');
  if (hashPos > 0) {
    remark = decodeURIComponent(uri.substring(hashPos + 1));
    uri = uri.substring(0, hashPos);
  }
  // 清理中间残留的 #
  const midHash = uri.indexOf('#');
  if (midHash > 0) {
    uri = uri.substring(0, midHash);
  }
  return { uri, remark };
}

/**
 * 从 query string 中提取 alpn 列表
 */
function getAlpnList(query) {
  const raw = getUrlArg(query, 'alpn');
  if (!raw) return [];
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

/**
 * 合并 query 参数
 */
function mergeParams(existing, query) {
  const parsed = typeof query === 'string' ? parseQueryString(query) : query;
  for (const [k, v] of Object.entries(parsed)) {
    if (v && !existing[k]) existing[k] = v;
  }
  return existing;
}

/**
 * 去除地址的方括号（IPv6）
 */
function unbracket(host) {
  if (host.startsWith('[') && host.endsWith(']')) {
    return host.slice(1, -1);
  }
  return host;
}

/**
 * 构建基础节点
 */
function buildNode(type, server, port, extras = {}) {
  const name = extras.name || extras.remarks || `${server}:${port}`;
  return { type, name, server: unbracket(server), port: parseInt(port) || port, ...extras };
}

// ═══════════════════════════════════════════════════════════
//  SS 加密套件白名单
// ═══════════════════════════════════════════════════════════

const SS_CIPHERS = new Set([
  'rc4-md5', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
  'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
  'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
  'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
  'bf-cfb', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
  'salsa20', 'chacha20', 'chacha20-ietf',
  '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305', '2022-blake3-chacha12-poly1305',
  '2022-blake3-chacha8-poly1305'
]);

// ═══════════════════════════════════════════════════════════
//  协议解析器
// ═══════════════════════════════════════════════════════════

// ---------- Shadowsocks (ss://) ----------

function parseSS(uri) {
  if (!uri.startsWith('ss://')) return null;
  let rest = uri.slice(5);

  // Handle /? → ?
  rest = rest.replace('/?', '?');

  // 提取 remarks
  const { uri: cleaned, remark } = extractRemark(rest);

  let password, method, server, port;
  let plugin = '', pluginOpts = '';
  let addition = '';

  // 分离 query string
  const qPos = cleaned.indexOf('?');
  if (qPos > 0) {
    addition = cleaned.substring(qPos + 1);
    rest = cleaned.substring(0, qPos);
  } else {
    rest = cleaned;
  }

  // SIP002 格式: method:password@server:port
  if (rest.includes('@')) {
    const atPos = rest.lastIndexOf('@');
    const userinfo = rest.substring(0, atPos);
    const hostpart = rest.substring(atPos + 1);

    // method:password
    const colonPos = userinfo.indexOf(':');
    if (colonPos < 0) return null;
    method = userinfo.substring(0, colonPos);
    password = userinfo.substring(colonPos + 1);

    // server:port
    const hostColon = hostpart.lastIndexOf(':');
    if (hostColon > 0) {
      server = hostpart.substring(0, hostColon);
      port = hostpart.substring(hostColon + 1);
    } else {
      server = hostpart;
      port = '8388';
    }
  } else {
    // Legacy base64 格式: base64(method:password@server:port)
    const decoded = urlSafeBase64Decode(rest);
    const m = decoded.match(/^(.+):(.+)@(.+):(\d+)$/);
    if (!m) return null;
    method = m[1];
    password = m[2];
    server = m[3];
    port = m[4];
  }

  if (!server || !port || port === '0') return null;

  // 提取 plugin
  const rawPlugin = getUrlArg(addition, 'plugin');
  if (rawPlugin) {
    const semiPos = rawPlugin.indexOf(';');
    plugin = semiPos > 0 ? rawPlugin.substring(0, semiPos) : rawPlugin;
    pluginOpts = semiPos > 0 ? rawPlugin.substring(semiPos + 1) : '';
  }

  const name = remark || `${server}:${port}`;
  const group = getUrlArg(addition, 'group');
  const udp = getUrlArg(addition, 'udp');
  const tfo = getUrlArg(addition, 'tfo');

  return {
    type: 'ss',
    name: group ? `${group} - ${name}` : name,
    server: unbracket(server),
    port: parseInt(port),
    password,
    cipher: method,
    plugin,
    pluginOpts,
    udp: udp !== '0' && udp !== 'false',
    tfo: tfo === '1' || tfo === 'true'
  };
}

// ---------- ShadowsocksR (ssr://) ----------

function parseSSR(uri) {
  if (!uri.startsWith('ssr://')) return null;
  let rest = uri.slice(6);
  rest = rest.replace(/\r/g, '');
  let decoded = urlSafeBase64Decode(rest);

  let obfsParam = '', protoParam = '', group = '', remarks = '';

  // 分离 /? obfs 参数
  const obfsPos = decoded.indexOf('/?');
  if (obfsPos > 0) {
    const obfsStr = decoded.substring(obfsPos + 2);
    decoded = decoded.substring(0, obfsPos);
    group = urlSafeBase64Decode(getUrlArg(obfsStr, 'group'));
    remarks = urlSafeBase64Decode(getUrlArg(obfsStr, 'remarks'));
    obfsParam = urlSafeBase64Decode(getUrlArg(obfsStr, 'obfsparam')).replace(/\s/g, '');
    protoParam = urlSafeBase64Decode(getUrlArg(obfsStr, 'protoparam')).replace(/\s/g, '');
  }

  // server:port:protocol:method:obfs:password
  const parts = decoded.split(':');
  if (parts.length < 6) return null;
  const [server, port, protocol, method, obfs, passwordB64] = parts;
  const password = urlSafeBase64Decode(passwordB64);

  if (!server || !port || port === '0') return null;

  const name = remarks || `${server}:${port}`;
  const grp = group || 'SSRProvider';

  // 如果 cipher 是 SS 套件且 obfs/protocol 都是 plain/origin → 当作 SS
  if (SS_CIPHERS.has(method) && (!obfs || obfs === 'plain') && (!protocol || protocol === 'origin')) {
    return {
      type: 'ss',
      name: `${grp} - ${name}`,
      server: unbracket(server),
      port: parseInt(port),
      password,
      cipher: method,
      plugin: '',
      pluginOpts: ''
    };
  }

  return {
    type: 'ssr',
    name: `${grp} - ${name}`,
    server: unbracket(server),
    port: parseInt(port),
    password,
    cipher: method,
    protocol,
    obfs,
    protocolParam: protoParam,
    obfsParam
  };
}

// ---------- VMess (vmess://) ----------

function parseVMess(uri) {
  if (!uri.startsWith('vmess://') && !uri.startsWith('vmess1://')) return null;

  // Shadowrocket style: vmess://base64?params
  if (/^vmess:\/\/[A-Za-z0-9+/\-_=]+\\?/.test(uri)) {
    return parseVMessShadowrocket(uri);
  }
  // Standard style: vmess://method+id@server:port?params
  if (/^vmess:\/\/[a-z]+\+?[a-z]*:/.test(uri)) {
    return parseVMessStandard(uri);
  }
  // Kitsunebi style: vmess1://id@server:port/path?params
  if (uri.startsWith('vmess1://')) {
    return parseVMessKitsunebi(uri);
  }

  // JSON style: vmess://base64json
  const b64 = uri.replace(/^(vmess|vmess1):\/\//, '');
  const decoded = urlSafeBase64Decode(b64);

  // Quantumult X style: name = vmess, server:port, ...
  if (decoded.includes(' = ')) {
    return parseVMessQuan(decoded);
  }

  // JSON
  try {
    const json = JSON.parse(decoded);
    if (json.add && json.port) {
      return parseVMessJson(json);
    }
  } catch {}

  return null;
}

function parseVMessJson(json) {
  const version = json.v || '1';
  const ps = json.ps || '';
  const add = (json.add || '').trim();
  const port = String(json.port);
  if (port === '0') return null;

  const type = json.type || 'none';
  const id = json.id || '';
  const aid = json.aid || '0';
  const net = json.net || 'tcp';
  const tlsVal = json.tls || '';
  let host = json.host || '';
  let path = '';
  const sni = json.sni || '';

  if (version === '1') {
    if (host) {
      const vArr = host.split(';');
      if (vArr.length === 2) {
        host = vArr[0];
        path = vArr[1];
      }
    }
  } else {
    path = json.path || '';
  }

  return buildNode('vmess', add, port, {
    name: ps || `${add}:${port}`,
    uuid: id || '00000000-0000-0000-0000-000000000000',
    alterId: parseInt(aid) || 0,
    cipher: json.scy || 'auto',
    network: net,
    tls: tlsVal === 'tls' ? 'tls' : 'none',
    host, path, sni
  });
}

function parseVMessShadowrocket(uri) {
  uri = uri.slice(8); // strip vmess://
  const qPos = uri.indexOf('?');
  const addition = qPos > 0 ? uri.substring(qPos + 1) : '';
  const encoded = qPos > 0 ? uri.substring(0, qPos) : uri;
  const decoded = urlSafeBase64Decode(encoded);

  // cipher:id@server:port
  const m = decoded.match(/^(.+):(.+)@(.+):(\d+)$/);
  if (!m) return null;
  const [, cipher, id, server, port] = m;
  if (port === '0') return null;

  const remarks = decodeURIComponent(getUrlArg(addition, 'remarks'));
  const obfs = getUrlArg(addition, 'obfs');
  let network = 'tcp', host = '', path = '';

  if (obfs) {
    if (obfs === 'websocket') {
      network = 'ws';
      host = getUrlArg(addition, 'obfsParam');
      path = getUrlArg(addition, 'path');
    }
  } else {
    network = getUrlArg(addition, 'network') || 'tcp';
    host = getUrlArg(addition, 'wsHost') || '';
    path = getUrlArg(addition, 'wspath') || '';
  }
  const tlsVal = getUrlArg(addition, 'tls') === '1' ? 'tls' : 'none';
  const aid = getUrlArg(addition, 'aid') || '0';

  return buildNode('vmess', server, port, {
    name: remarks || `${server}:${port}`,
    uuid: id,
    alterId: parseInt(aid) || 0,
    cipher: cipher || 'auto',
    network, tls: tlsVal, host, path
  });
}

function parseVMessStandard(uri) {
  uri = uri.slice(8); // strip vmess://
  const { uri: cleaned, remark } = extractRemark(uri);
  // net(+tls):uuid-aid@server:port/?params
  const m = cleaned.match(/^([a-z]+)(?:\+([a-z]+))?:([\da-f]{4}(?:[\da-f]{4}-){4}[\da-f]{12})-(\d+)@(.+):(\d+)(?:\/?(.*))?$/i);
  if (!m) return null;
  const [, net, tlsType, uuid, aid, server, port, addition] = m;

  let type = '', host = '', path = '';
  switch (net) {
    case 'tcp':
    case 'kcp':
      type = getUrlArg(addition, 'type');
      break;
    case 'http':
    case 'ws':
      host = getUrlArg(addition, 'host');
      path = getUrlArg(addition, 'path');
      break;
    case 'quic':
      type = getUrlArg(addition, 'security');
      host = getUrlArg(addition, 'type');
      path = getUrlArg(addition, 'key');
      break;
  }

  return buildNode('vmess', server, port, {
    name: remark || `${server}:${port}`,
    uuid,
    alterId: parseInt(aid) || 0,
    cipher: 'auto',
    network: net,
    tls: tlsType === 'tls' ? 'tls' : 'none',
    host, path
  });
}

function parseVMessKitsunebi(uri) {
  uri = uri.slice(9); // strip vmess1://
  const { uri: cleaned, remark } = extractRemark(uri);
  const qPos = cleaned.indexOf('?');
  const addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  const base = qPos > 0 ? cleaned.substring(0, qPos) : cleaned;

  // id@server:port/path
  const m = base.match(/^(.+)@(.+):(\d+)(\/.*)?$/);
  if (!m) return null;
  const [, id, server, port, pathSuffix] = m;
  if (port === '0') return null;

  const path = pathSuffix || '';
  const network = getUrlArg(addition, 'network') || 'tcp';
  const tlsVal = getUrlArg(addition, 'tls') === 'true' ? 'tls' : 'none';
  const host = getUrlArg(addition, 'ws.host') || '';

  return buildNode('vmess', server, port, {
    name: remark || `${server}:${port}`,
    uuid: id,
    alterId: 0,
    cipher: 'auto',
    network, tls: tlsVal, host, path
  });
}

function parseVMessQuan(str) {
  // name = vmess, server, port, cipher, id, ...
  const m = str.match(/^(.*?) = vmess,(.*)$/);
  if (!m) return null;
  const ps = m[1].trim();
  const configs = m[2].split(',');
  if (configs.length < 5) return null;

  const add = configs[0].trim();
  const port = configs[1].trim();
  if (port === '0') return null;
  const cipher = configs[2].trim();
  const id = configs[3].trim().replace(/"/g, '');

  let group = 'V2RayProvider', tls = 'none', host = '', path = '/', network = 'tcp', edge = '';

  for (let i = 4; i < configs.length; i++) {
    const eqPos = configs[i].indexOf('=');
    if (eqPos < 0) continue;
    const key = configs[i].substring(0, eqPos).trim();
    let val = configs[i].substring(eqPos + 1).trim();

    switch (key) {
      case 'group': group = val; break;
      case 'over-tls': tls = val === 'true' ? 'tls' : 'none'; break;
      case 'tls-host': host = val; break;
      case 'obfs-path': path = val.replace(/"/g, ''); break;
      case 'obfs':
        if (val === 'ws') network = 'ws';
        break;
      case 'obfs-header':
        const headers = val.replace(/"/g, '').replace(/[Rr][Nn]/g, '|').split('|');
        for (const h of headers) {
          if (/host:/i.test(h)) host = h.substring(5).trim();
          if (/edge:/i.test(h)) edge = h.substring(5).trim();
        }
        break;
    }
  }
  if (!path) path = '/';

  return buildNode('vmess', add, port, {
    name: `${group} - ${ps}`,
    uuid: id, alterId: 0, cipher, network, tls, host, path, edge
  });
}

// ---------- Trojan ----------

function parseTrojan(uri) {
  if (!uri.startsWith('trojan://') && !uri.startsWith('trojan-go://')) return null;
  uri = uri.replace(/^trojan-go:\/\//, 'trojan://');
  let rest = uri.slice(9);

  const { uri: cleaned, remark } = extractRemark(rest);
  const qPos = cleaned.indexOf('?');
  const addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  const base = qPos > 0 ? cleaned.substring(0, qPos) : cleaned;

  // password@server:port
  const m = base.match(/^(.+)@(.+):(\d+)$/);
  if (!m) return null;
  const [, password, server, port] = m;
  if (port === '0') return null;

  let sni = getUrlArg(addition, 'sni');
  let host = getUrlArg(addition, 'host') || sni;
  if (!host) host = getUrlArg(addition, 'peer');
  const tfo = getUrlArg(addition, 'tfo');
  const fp = getUrlArg(addition, 'fp');
  const scv = getUrlArg(addition, 'allowInsecure');
  const group = decodeURIComponent(getUrlArg(addition, 'group'));

  let network = 'tcp', path = '';
  if (getUrlArg(addition, 'ws') === '1') {
    path = getUrlArg(addition, 'wspath');
    network = 'ws';
  } else if (getUrlArg(addition, 'type') === 'ws') {
    path = getUrlArg(addition, 'path');
    if (path.startsWith('%2F')) path = decodeURIComponent(path);
    network = 'ws';
  } else if (getUrlArg(addition, 'type') === 'grpc') {
    path = getUrlArg(addition, 'serviceName');
    network = 'grpc';
  }

  const name = remark || `${server}:${port}`;

  return buildNode('trojan', server, port, {
    name: group ? `${group} - ${name}` : name,
    password, sni: sni || host || server, host, network, path,
    fingerprint: fp || 'chrome',
    skipCertVerify: scv === '1' || scv === 'true',
    udp: true,
    tfo: tfo === '1' || tfo === 'true'
  });
}

// ---------- VLESS ----------

function parseVLESS(uri) {
  if (!uri.startsWith('vless://') && !uri.startsWith('vless1://')) return null;
  let rest = uri.replace(/^vless1?:\/\//, '');

  const { uri: cleaned, remark } = extractRemark(rest);
  const qPos = cleaned.indexOf('?');
  const addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';

  // uuid@server:port
  const m = cleaned.match(/^([\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12})@\[?([\d\-a-zA-Z:.]+)\]?:(\d+)(?:\/?(.*))?$/);
  if (!m) return null;
  const [, id, server, port] = m;
  if (!server || !port || port === '0') return null;

  const tlsVal = getUrlArg(addition, 'security') || 'none';
  const net = getUrlArg(addition, 'type') || 'tcp';
  const flow = getUrlArg(addition, 'flow');
  const pbk = getUrlArg(addition, 'pbk');
  const sid = getUrlArg(addition, 'sid');
  const encryption = getUrlArg(addition, 'encryption');
  const fp = getUrlArg(addition, 'fp') || 'chrome';
  const packetEncoding = getUrlArg(addition, 'packet-encoding');
  const alpnList = getAlpnList(addition);

  let type = '', host = '', path = '', mode = '';

  switch (net) {
    case 'tcp':
    case 'http':
    case 'ws':
    case 'h2':
      type = getUrlArg(addition, 'headerType');
      host = getUrlArg(addition, addition.includes('sni') ? 'sni' : 'host');
      path = getUrlArg(addition, 'path');
      break;
    case 'grpc':
      host = getUrlArg(addition, 'sni');
      path = getUrlArg(addition, 'serviceName');
      mode = getUrlArg(addition, 'mode');
      break;
    case 'quic':
      type = getUrlArg(addition, 'headerType');
      host = getUrlArg(addition, addition.includes('sni') ? 'sni' : 'quicSecurity');
      path = getUrlArg(addition, 'key');
      break;
    case 'xhttp':
      host = getUrlArg(addition, addition.includes('sni') ? 'sni' : 'host');
      path = getUrlArg(addition, 'path');
      break;
  }

  const sni = getUrlArg(addition, 'sni') || host;

  const name = remark || `${server}:${port}`;

  return buildNode('vless', server, port, {
    name,
    uuid: id || '00000000-0000-0000-0000-000000000000',
    alterId: 0,
    cipher: 'auto',
    network: net,
    tls: tlsVal,
    flow,
    fingerprint: fp,
    publicKey: pbk,
    shortId: sid,
    encryption,
    packetEncoding,
    sni,
    host,
    path,
    mode,
    alpn: alpnList
  });
}

// ---------- Hysteria ----------

function parseHysteria(uri) {
  if (!uri.startsWith('hysteria://') && !uri.startsWith('hy://')) return null;
  uri = uri.replace(/^hy:\/\//, 'hysteria://');
  let rest = uri.slice(11);

  const { uri: cleaned, remark } = extractRemark(rest);
  const qPos = cleaned.indexOf('?');
  const addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';

  // server:port
  const m = cleaned.match(/^(.+):(\d+)\?(.*)$/);
  if (!m) return null;
  const [, server, port, extra] = m;
  const mergedQuery = extra + '&' + addition;

  const type = getUrlArg(mergedQuery, 'protocol');
  const auth = getUrlArg(mergedQuery, 'auth');
  const authStr = getUrlArg(mergedQuery, 'auth_str');
  const peer = getUrlArg(mergedQuery, 'peer');
  const insecure = getUrlArg(mergedQuery, 'insecure');
  const up = getUrlArg(mergedQuery, 'upmbps');
  const down = getUrlArg(mergedQuery, 'downmbps');
  const alpn = getAlpnList(mergedQuery).join(',');
  const obfsParam = getUrlArg(mergedQuery, 'obfsParam');
  const sni = peer || server;

  const name = remark || `${server}:${port}`;

  return buildNode('hysteria', server, port, {
    name,
    auth: auth || authStr,
    peer: peer || server,
    insecure: insecure === '1',
    upMbps: up,
    downMbps: down,
    alpn,
    obfs: obfsParam,
    sni,
    protocol: type,
    udp: true
  });
}

// ---------- Hysteria2 ----------

function parseHysteria2(uri) {
  if (!uri.startsWith('hysteria2://') && !uri.startsWith('hy2://')) return null;
  uri = uri.replace(/^hy2:\/\//, 'hysteria2://');
  let rest = uri.slice(12);
  rest = rest.replace('/?', '?');

  const { uri: cleaned, remark } = extractRemark(rest);
  const qPos = cleaned.indexOf('?');
  const addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  const base = qPos > 0 ? cleaned.substring(0, qPos) : cleaned;

  let password, server, port;

  if (base.includes('@')) {
    // password@server:port
    const m = base.match(/^(.+)@(.+):(\d+)$/);
    if (!m) return null;
    [, password, server, port] = m;
  } else {
    // server:port (password in query)
    const m = base.match(/^(.+):(\d+)$/);
    if (!m) return null;
    [, server, port] = m;
    password = getUrlArg(addition, 'password');
  }

  if (!server || !port || port === '0') return null;

  const scv = getUrlArg(addition, 'insecure');
  const up = getUrlArg(addition, 'up');
  const down = getUrlArg(addition, 'down');
  const alpn = getAlpnList(addition).join(',');
  const obfs = getUrlArg(addition, 'obfs');
  const obfsPassword = getUrlArg(addition, 'obfs-password');
  const sni = getUrlArg(addition, 'sni');
  const ports = getUrlArg(addition, 'ports');

  const name = remark || `${server}:${port}`;

  return buildNode('hysteria2', server, port, {
    name,
    password: password || '',
    sni: sni || server,
    insecure: scv === '1' || scv === 'true',
    upMbps: up,
    downMbps: down,
    alpn,
    obfs,
    obfsPassword,
    ports,
    udp: true
  });
}

// ---------- TUIC ----------

function parseTUIC(uri) {
  if (!uri.startsWith('tuic://')) return null;
  let rest = uri.slice(7);

  const { uri: cleaned, remark } = extractRemark(rest);
  const qPos = cleaned.indexOf('?');
  const addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  const base = qPos > 0 ? cleaned.substring(0, qPos) : cleaned;

  // uuid:password@server:port
  const m = base.match(/^([^:]+):(.+)@(.+):(\d+)$/);
  if (!m) return null;
  const [, uuid, password, server, port] = m;
  if (!server || !port || port === '0') return null;

  const scv = getUrlArg(addition, 'insecure');
  const alpn = getAlpnList(addition).join(',');
  const sni = getUrlArg(addition, 'sni');
  const congestionControl = getUrlArg(addition, 'congestion_control') || 'bbr';

  const name = remark || `${server}:${port}`;

  return buildNode('tuic', server, port, {
    name,
    uuid: uuid || '00000000-0000-0000-0000-000000000000',
    password,
    sni: sni || server,
    alpn,
    congestionControl,
    udpRelayMode: 'native',
    skipCertVerify: scv === '1' || scv === 'true',
    udp: true
  });
}

// ---------- AnyTLS ----------

function parseAnyTLS(uri) {
  if (!uri.startsWith('anytls://')) return null;
  let rest = uri.slice(9);

  const { uri: cleaned, remark } = extractRemark(rest);
  const qPos = cleaned.indexOf('?');
  const addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  const base = qPos > 0 ? cleaned.substring(0, qPos) : cleaned;

  // password@server:port
  let password, server, port;
  const atPos = base.indexOf('@');
  if (atPos > 0) {
    password = base.substring(0, atPos);
    const hostPart = base.substring(atPos + 1);
    const colonPos = hostPart.lastIndexOf(':');
    if (colonPos > 0) {
      server = hostPart.substring(0, colonPos);
      port = hostPart.substring(colonPos + 1);
    } else {
      return null;
    }
  } else {
    return null;
  }

  if (!server || !port || port === '0') return null;

  const alpnList = getAlpnList(addition);
  let fp = getUrlArg(addition, 'fp');
  if (!fp) fp = getUrlArg(addition, 'fingerprint');
  if (!fp) fp = decodeURIComponent(getUrlArg(addition, 'hpkp'));
  let sni = getUrlArg(addition, 'sni');
  if (!sni) sni = getUrlArg(addition, 'peer');
  const udp = getUrlArg(addition, 'udp');
  const tfo = getUrlArg(addition, 'tfo');
  const scv = getUrlArg(addition, 'insecure');

  const name = remark || `${server}:${port}`;

  return buildNode('anytls', server, port, {
    name,
    password,
    sni: sni || server,
    fingerprint: fp || 'chrome',
    alpn: alpnList,
    skipCertVerify: scv === '1' || scv === 'true',
    udp: udp !== '0' && udp !== 'false',
    tfo: tfo === '1' || tfo === 'true'
  });
}

// ---------- SOCKS5 ----------

function parseSOCKS(uri) {
  if (uri.startsWith('socks://')) {
    // V2RayN 风格: socks://base64(user:pass@server:port)#name
    let rest = uri.slice(8);
    const { uri: cleaned, remark } = extractRemark(rest);
    let decoded = urlSafeBase64Decode(cleaned);
    let username = '', password = '', server, port;

    if (decoded.includes('@')) {
      const parts = decoded.split('@');
      if (parts.length < 2) return null;
      decoded = parts[1];
      const userinfo = parts[0].split(':');
      if (userinfo.length >= 2) {
        username = userinfo[0];
        password = userinfo[1];
      }
    }
    const hostParts = decoded.split(':');
    if (hostParts.length < 2) return null;
    server = hostParts[0];
    port = hostParts[1];
    if (port === '0') return null;

    const name = remark || `${server}:${port}`;
    return buildNode('socks5', server, port, { name, username, password });
  }

  // Telegram 风格: tg://socks?server=... or https://t.me/socks?server=...
  if (uri.includes('t.me/socks') || uri.startsWith('tg://socks')) {
    const server = getUrlArg(uri, 'server');
    const port = getUrlArg(uri, 'port');
    if (!server || !port || port === '0') return null;
    const username = decodeURIComponent(getUrlArg(uri, 'user'));
    const password = decodeURIComponent(getUrlArg(uri, 'pass'));
    const remarks = decodeURIComponent(getUrlArg(uri, 'remarks'));
    const group = decodeURIComponent(getUrlArg(uri, 'group'));

    const name = remarks || `${server}:${port}`;
    return buildNode('socks5', server, port, {
      name: group ? `${group} - ${name}` : name,
      username, password
    });
  }
  return null;
}

// ---------- HTTP(S) ----------

function parseHTTP(uri) {
  // Telegram 风格: https://t.me/http?server=... or tg://http?server=...
  if (uri.includes('t.me/http') || uri.startsWith('tg://http')) {
    const server = getUrlArg(uri, 'server');
    const port = getUrlArg(uri, 'port');
    if (!server || !port || port === '0') return null;
    const username = decodeURIComponent(getUrlArg(uri, 'user'));
    const password = decodeURIComponent(getUrlArg(uri, 'pass'));
    const remarks = decodeURIComponent(getUrlArg(uri, 'remarks'));
    const group = decodeURIComponent(getUrlArg(uri, 'group'));
    const isTLS = uri.includes('/https');

    const name = remarks || `${server}:${port}`;
    return buildNode(isTLS ? 'https' : 'http', server, port, {
      name: group ? `${group} - ${name}` : name,
      username, password, tls: isTLS
    });
  }

  // 标准 HTTP 代理订阅链接: http(s)://base64(user:pass@server:port)?remarks=...
  if (/^https?:\/\//.test(uri)) {
    let isTLS = uri.startsWith('https://');
    let rest = uri.replace(/^https?:\/\//, '');
    const qPos = rest.indexOf('?');
    const addition = qPos > 0 ? rest.substring(qPos + 1) : '';
    if (qPos > 0) rest = rest.substring(0, qPos);

    const remarks = decodeURIComponent(getUrlArg(addition, 'remarks'));
    const group = decodeURIComponent(getUrlArg(addition, 'group'));
    let decoded = urlSafeBase64Decode(rest);

    let username = '', password = '', server, port;
    if (decoded.includes('@')) {
      const m = decoded.match(/^(.+):(.+)@(.+):(\d+)$/);
      if (m) {
        [, username, password, server, port] = m;
      }
    } else {
      const m = decoded.match(/^(.+):(\d+)$/);
      if (m) {
        [, server, port] = m;
      }
    }

    if (!server || !port || port === '0') return null;
    const name = remarks || `${server}:${port}`;
    return buildNode(isTLS ? 'https' : 'http', server, port, {
      name: group ? `${group} - ${name}` : name,
      username, password, tls: isTLS
    });
  }
  return null;
}

// ---------- Clash YAML ----------

function parseClashYAML(content) {
  const nodes = [];
  // 尝试用简单方式解析 YAML 格式的 proxies 部分
  // 匹配 proxies: 块
  const proxyMatch = content.match(/^(?:Proxy|proxies):\s*\n((?:\s+-.*(?:\n|$))+)/m);
  if (!proxyMatch) return nodes;

  // 按 - 分割每个 proxy 条目
  const entries = proxyMatch[1].split(/\n\s*- /).filter(Boolean);
  for (const entry of entries) {
    const proxy = parseClashProxyEntry(entry.trim());
    if (proxy) nodes.push(proxy);
  }
  return nodes;
}

function parseClashProxyEntry(entry) {
  // 简化 YAML 解析：按 key: value 提取字段
  const fields = {};
  const lines = entry.split('\n');
  let currentKey = '';
  for (const line of lines) {
    const kvMatch = line.match(/^\s*(\S[^:]*?):\s*(.*)/);
    if (kvMatch) {
      currentKey = kvMatch[1].trim();
      fields[currentKey] = kvMatch[2].trim();
    } else {
      // 多行值
      const mvMatch = line.match(/^\s+-\s+(.*)/);
      if (mvMatch) {
        if (!Array.isArray(fields[currentKey])) fields[currentKey] = [];
        fields[currentKey].push(mvMatch[1].trim());
      }
    }
  }

  const type = fields.type;
  const name = fields.name || '';
  const server = fields.server || '';
  const port = fields.port || '0';
  if (!type || !server || port === '0') return null;

  const base = { name, server: unbracket(server), port: parseInt(port) };

  switch (type) {
    case 'ss':
      return {
        type: 'ss', ...base,
        cipher: fields.cipher || '',
        password: fields.password || '',
        plugin: fields.plugin || '',
        pluginOpts: fields['plugin-opts'] || '',
        udp: fields.udp === 'true'
      };
    case 'ssr':
      return {
        type: 'ssr', ...base,
        cipher: fields.cipher || '',
        password: fields.password || '',
        protocol: fields.protocol || 'origin',
        protocolParam: fields['protocol-param'] || fields.protocolparam || '',
        obfs: fields.obfs || 'plain',
        obfsParam: fields['obfs-param'] || fields.obfsparam || ''
      };
    case 'vmess':
      return {
        type: 'vmess', ...base,
        uuid: fields.uuid || '',
        alterId: parseInt(fields.alterId) || 0,
        cipher: fields.cipher || 'auto',
        network: fields.network || 'tcp',
        tls: fields.tls === 'true' ? 'tls' : 'none',
        host: fields['ws-opts'] ? '' : (fields['ws-headers']?.['Host'] || ''),
        path: fields['ws-path'] || '/',
        sni: fields.servername || ''
      };
    case 'trojan':
      return {
        type: 'trojan', ...base,
        password: fields.password || '',
        sni: fields.sni || server,
        network: fields.network || 'tcp',
        udp: fields.udp === 'true'
      };
    case 'vless':
      return {
        type: 'vless', ...base,
        uuid: fields.uuid || '',
        network: fields.network || 'tcp',
        tls: fields.tls === 'true' ? 'tls' : 'none',
        sni: fields.sni || fields.servername || '',
        flow: fields.flow || ''
      };
    case 'hysteria':
      return {
        type: 'hysteria', ...base,
        auth: fields['auth-str'] || fields.auth_str || fields.password || '',
        upMbps: fields.up || '',
        downMbps: fields.down || '',
        sni: fields.sni || server,
        obfs: fields.obfs || ''
      };
    case 'hysteria2':
      return {
        type: 'hysteria2', ...base,
        password: fields.password || fields.auth || '',
        upMbps: fields.up || '',
        downMbps: fields.down || '',
        sni: fields.sni || server,
        obfs: fields.obfs || ''
      };
    case 'tuic':
      return {
        type: 'tuic', ...base,
        password: fields.password || '',
        uuid: fields.uuid || '',
        sni: fields.sni || server,
        congestionControl: fields['congestion-controller'] || 'bbr',
        alpn: fields.alpn || ''
      };
    case 'http':
      return {
        type: 'http', ...base,
        username: fields.username || '',
        password: fields.password || '',
        tls: fields.tls === 'true'
      };
    case 'socks5':
      return {
        type: 'socks5', ...base,
        username: fields.username || '',
        password: fields.password || ''
      };
    case 'snell':
      return {
        type: 'snell', ...base,
        password: fields.psk || '',
        obfs: fields['obfs-opts']?.mode || '',
        host: fields['obfs-opts']?.host || '',
        version: parseInt(fields.version) || 0
      };
    case 'wireguard':
      return {
        type: 'wireguard', ...base,
        privateKey: fields['private-key'] || '',
        publicKey: fields['public-key'] || '',
        preSharedKey: fields['preshared-key'] || '',
        selfIp: fields.ip || '',
        selfIpv6: fields.ipv6 || '',
        mtu: parseInt(fields.mtu) || 0
      };
    default:
      return null;
  }
}

// ═══════════════════════════════════════════════════════════
//  主分发
// ═══════════════════════════════════════════════════════════

/**
 * 解析单个代理链接
 * @param {string} uri - 代理链接
 * @returns {ProxyNode|null}
 */
function parseNode(uri) {
  if (!uri || typeof uri !== 'string') return null;
  uri = uri.trim();
  if (!uri || uri.startsWith('#') || uri.startsWith('//')) return null;

  // 按协议分发
  if (uri.startsWith('ssr://'))      return parseSSR(uri);
  if (uri.startsWith('ss://'))       return parseSS(uri);
  if (uri.startsWith('vmess://') || uri.startsWith('vmess1://')) return parseVMess(uri);
  if (uri.startsWith('trojan://') || uri.startsWith('trojan-go://')) return parseTrojan(uri);
  if (uri.startsWith('vless://') || uri.startsWith('vless1://')) return parseVLESS(uri);
  if (uri.startsWith('hysteria://') || uri.startsWith('hy://')) return parseHysteria(uri);
  if (uri.startsWith('hysteria2://') || uri.startsWith('hy2://')) return parseHysteria2(uri);
  if (uri.startsWith('tuic://'))     return parseTUIC(uri);
  if (uri.startsWith('anytls://'))   return parseAnyTLS(uri);
  if (uri.startsWith('socks://') || uri.includes('t.me/socks') || uri.startsWith('tg://socks')) return parseSOCKS(uri);
  if (uri.includes('t.me/http') || uri.startsWith('tg://http')) return parseHTTP(uri);

  // 普通 http(s):// 链接 → 尝试 http 代理
  if (/^https?:\/\//.test(uri)) {
    // 先尝试作为 HTTP 代理
    const httpNode = parseHTTP(uri);
    if (httpNode) return httpNode;
  }

  return null;
}

/**
 * 解析订阅内容（多行多格式）
 * @param {string} content - 订阅内容（原始或 base64）
 * @returns {ProxyNode[]}
 */
function parseSubscription(content) {
  if (!content || typeof content !== 'string') return [];
  content = content.trim();
  if (!content) return [];

  const nodes = [];

  // 0. SSD 格式
  if (content.startsWith('ssd://')) {
    return parseSSD(content);
  }

  // 1. Clash YAML 格式
  if (/"?[Pp]rox(?:y|ies)"?\s*:/.test(content)) {
    const clashNodes = parseClashYAML(content);
    if (clashNodes.length > 0) return clashNodes;
  }

  // 2. Sing-box JSON 格式
  if (content.includes('"outbounds"') && content.includes('"type"')) {
    try {
      const json = JSON.parse(content);
      if (json.outbounds) {
        return parseSingboxOutbounds(json.outbounds);
      }
    } catch {}
  }

  // 3. Surge 格式
  if (/\[Proxy\]/.test(content)) {
    return parseSurgeConf(content);
  }

  // 4. 尝试 base64 解码
  let decoded = content;
  // 检测是否为 base64（不含常见协议前缀时）
  if (!content.includes('://') && !content.includes(' = ')) {
    try {
      decoded = urlSafeBase64Decode(content);
      // 如果解码后包含协议前缀，说明确实是 base64
      if (!decoded.includes('://') && !decoded.includes(' = ')) {
        decoded = content; // 解码失败，恢复原样
      }
    } catch {}
  }

  // 5. Surge 风格（解码后）: key = ss, server, port, ...
  if (decoded.includes(' = ') && /(vmess|ss|trojan|http|shadowsocks)\s*=/.test(decoded)) {
    return parseSurgeLike(decoded);
  }

  // 6. 按行解析
  // 根据换行符选择分隔符
  const newlineCount = (decoded.match(/\n/g) || []).length;
  const crCount = (decoded.match(/\r/g) || []).length;
  let delimiter = '\n';
  if (newlineCount < 1 && crCount >= 1) delimiter = '\r';
  else if (newlineCount < 1 && crCount < 1) delimiter = '|'; // 管道分隔

  const lines = decoded.split(delimiter);
  for (const line of lines) {
    const node = parseNode(line.trim());
    if (node) nodes.push(node);
  }

  return nodes;
}

// ---------- SSD ----------

function parseSSD(uri) {
  // ssd://base64json
  const b64 = uri.slice(6);
  const decoded = urlSafeBase64Decode(b64);
  let json;
  try { json = JSON.parse(decoded); } catch { return []; }
  if (!json.servers) return [];

  const group = json.airport || '';
  const defaultPort = json.port || '';
  const defaultMethod = json.encryption || '';
  const defaultPassword = json.password || '';
  const defaultPlugin = json.plugin || '';
  const defaultPluginOpts = json.plugin_options || '';

  const nodes = [];
  let serverList = [];

  if (Array.isArray(json.servers)) {
    serverList = json.servers;
  } else if (typeof json.servers === 'object') {
    serverList = Object.values(json.servers);
  }

  for (const s of serverList) {
    const server = s.server || '';
    const port = s.port || defaultPort;
    if (!server || !port || port === '0') continue;

    const remarks = s.remarks || `${server}:${port}`;
    const method = s.encryption || defaultMethod;
    const password = s.password || defaultPassword;
    const plugin = s.plugin || defaultPlugin;
    const pluginOpts = s.plugin_options || defaultPluginOpts;

    nodes.push(buildNode('ss', server, port, {
      name: group ? `${group} - ${remarks}` : remarks,
      cipher: method,
      password,
      plugin,
      pluginOpts
    }));
  }
  return nodes;
}

// ---------- Sing-box ----------

function parseSingboxOutbounds(outbounds) {
  if (!Array.isArray(outbounds)) return [];
  const nodes = [];
  for (const item of outbounds) {
    if (!item || !item.type) continue;
    const base = {
      name: item.tag || '',
      server: item.server || '',
      port: parseInt(item.server_port) || 0
    };
    if (!base.server || !base.port) continue;

    let tlsObj = item.tls || {};
    let tlsEnabled = tlsObj.enabled === true;
    let sni = tlsObj.server_name || '';
    let alpn = (tlsObj.alpn && Array.isArray(tlsObj.alpn)) ? tlsObj.alpn.join(',') : '';
    let insecure = tlsObj.insecure === true;

    switch (item.type) {
      case 'vmess':
        nodes.push({ type: 'vmess', ...base,
          uuid: item.uuid || '', alterId: parseInt(item.alter_id) || 0,
          cipher: item.security || 'auto', network: item.transport?.type || 'tcp',
          tls: tlsEnabled ? 'tls' : 'none', sni, host: item.transport?.host || '',
          path: item.transport?.path || '' });
        break;
      case 'shadowsocks':
        nodes.push({ type: 'ss', ...base,
          cipher: item.method || '', password: item.password || '',
          plugin: item.plugin || '', pluginOpts: item.plugin_opts || '' });
        break;
      case 'trojan':
        nodes.push({ type: 'trojan', ...base,
          password: item.password || '', sni, network: item.transport?.type || 'tcp',
          path: item.transport?.path || '' });
        break;
      case 'vless':
        nodes.push({ type: 'vless', ...base,
          uuid: item.uuid || '', flow: item.flow || '', encryption: item.encryption || '',
          network: item.transport?.type || 'tcp', tls: tlsEnabled ? (tlsObj.reality ? 'reality' : 'tls') : 'none',
          sni, publicKey: tlsObj.reality?.public_key || '', shortId: tlsObj.reality?.short_id || '' });
        break;
      case 'hysteria':
        nodes.push({ type: 'hysteria', ...base,
          auth: item.auth_str || '', upMbps: item.up || item.up_mbps || '',
          downMbps: item.down || item.down_mbps || '', sni, obfs: item.obfs || '' });
        break;
      case 'hysteria2':
        nodes.push({ type: 'hysteria2', ...base,
          password: item.password || '', upMbps: item.up || '', downMbps: item.down || '',
          sni, obfs: item.obfs?.type || '', obfsPassword: item.obfs?.password || '' });
        break;
      case 'tuic':
        nodes.push({ type: 'tuic', ...base,
          password: item.password || '', uuid: item.uuid || '', sni,
          congestionControl: item.congestion_control || 'bbr', alpn,
          udpRelayMode: item.udp_relay_mode || 'native' });
        break;
      case 'http':
        nodes.push({ type: 'http', ...base,
          username: item.username || '', password: item.password || '',
          tls: tlsEnabled });
        break;
      case 'socks':
        nodes.push({ type: 'socks5', ...base,
          username: item.username || '', password: item.password || '' });
        break;
      case 'wireguard':
        nodes.push({ type: 'wireguard', ...base,
          privateKey: item.private_key || '', publicKey: item.public_key || '',
          preSharedKey: item.pre_shared_key || '', selfIp: item.inet4_bind_address || '',
          mtu: parseInt(item.mtu) || 0 });
        break;
    }
  }
  return nodes;
}

// ---------- Surge ----------

function parseSurgeConf(content) {
  const nodes = [];
  // 提取 [Proxy] 段
  const proxyMatch = content.match(/\[Proxy\]\r?\n([\s\S]*?)(?:\r?\n\[|$)/);
  if (!proxyMatch) return nodes;

  const lines = proxyMatch[1].split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(';') || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;

    // name = type, server, port, ...
    const eqPos = trimmed.indexOf('=');
    if (eqPos < 0) continue;
    const name = trimmed.substring(0, eqPos).trim();
    const value = trimmed.substring(eqPos + 1).trim();
    const parts = value.split(',').map(s => s.trim());

    if (parts.length < 3) continue;
    const type = parts[0];
    const server = parts[1];
    const port = parts[2];
    if (port === '0') continue;

    switch (type) {
      case 'ss': {
        let method = '', password = '', obfs = '', obfsHost = '', udp = false, tfo = false;
        for (let i = 3; i < parts.length; i++) {
          const kv = parts[i].split('=');
          if (kv.length < 2) continue;
          switch (kv[0].trim()) {
            case 'encrypt-method': method = kv[1].trim(); break;
            case 'password': password = kv[1].trim(); break;
            case 'obfs': obfs = kv[1].trim(); break;
            case 'obfs-host': obfsHost = kv[1].trim(); break;
            case 'udp-relay': udp = kv[1].trim() === 'true'; break;
            case 'tfo': tfo = kv[1].trim() === 'true'; break;
          }
        }
        nodes.push(buildNode('ss', server, port, {
          name, cipher: method, password,
          plugin: obfs ? 'obfs-local' : '',
          pluginOpts: obfs ? `obfs=${obfs}${obfsHost ? ';obfs-host=' + obfsHost : ''}` : '',
          udp, tfo
        }));
        break;
      }
      case 'vmess': {
        let id = '', ws = 'tcp', tls = 'none', path = '/', host = '', udp = false, tfo = false, scv = false, aead = '0';
        for (let i = 3; i < parts.length; i++) {
          const kv = parts[i].split('=');
          if (kv.length < 2) continue;
          switch (kv[0].trim()) {
            case 'username': id = kv[1].trim(); break;
            case 'ws': ws = kv[1].trim() === 'true' ? 'ws' : 'tcp'; break;
            case 'tls': tls = kv[1].trim() === 'true' ? 'tls' : 'none'; break;
            case 'ws-path': path = kv[1].trim(); break;
            case 'obfs-host': host = kv[1].trim(); break;
            case 'udp-relay': udp = kv[1].trim() === 'true'; break;
            case 'tfo': tfo = kv[1].trim() === 'true'; break;
            case 'skip-cert-verify': scv = kv[1].trim() === 'true'; break;
            case 'vmess-aead': aead = kv[1].trim() === 'true' ? '0' : '1'; break;
          }
        }
        nodes.push(buildNode('vmess', server, port, {
          name, uuid: id, alterId: parseInt(aead) || 0, cipher: 'auto',
          network: ws, tls, host, path, udp, tfo, skipCertVerify: scv
        }));
        break;
      }
      case 'trojan': {
        let password = '', sni = '', udp = false;
        for (let i = 3; i < parts.length; i++) {
          const kv = parts[i].split('=');
          if (kv.length < 2) continue;
          switch (kv[0].trim()) {
            case 'password': password = kv[1].trim(); break;
            case 'sni': sni = kv[1].trim(); break;
            case 'udp-relay': udp = kv[1].trim() === 'true'; break;
          }
        }
        nodes.push(buildNode('trojan', server, port, {
          name, password, sni: sni || server, udp
        }));
        break;
      }
      case 'http': {
        let username = '', password = '';
        for (let i = 3; i < parts.length; i++) {
          const kv = parts[i].split('=');
          if (kv.length < 2) continue;
          switch (kv[0].trim()) {
            case 'username': username = kv[1].trim(); break;
            case 'password': password = kv[1].trim(); break;
          }
        }
        nodes.push(buildNode('http', server, port, { name, username, password }));
        break;
      }
      case 'socks5': {
        let username = '', password = '';
        if (parts.length >= 5) {
          username = parts[3];
          password = parts[4];
        }
        nodes.push(buildNode('socks5', server, port, { name, username, password }));
        break;
      }
      // custom / direct / reject 跳过
      case 'custom': {
        // custom = server, port, method, password, module, ...
        if (parts.length >= 5) {
          const method = parts[3];
          const password = parts[4];
          let obfs = '', obfsHost = '';
          for (let i = 6; i < parts.length; i++) {
            const kv = parts[i].split('=');
            if (kv.length < 2) continue;
            if (kv[0].trim() === 'obfs') obfs = kv[1].trim();
            if (kv[0].trim() === 'obfs-host') obfsHost = kv[1].trim();
          }
          nodes.push(buildNode('ss', server, port, {
            name, cipher: method, password,
            plugin: obfs ? 'obfs-local' : '',
            pluginOpts: obfs ? `obfs=${obfs}${obfsHost ? ';obfs-host=' + obfsHost : ''}` : ''
          }));
        }
        break;
      }
    }
  }
  return nodes;
}

// ---------- Surge-like (decoded base64 with "key = value") ----------

function parseSurgeLike(content) {
  const nodes = [];
  const lines = content.split(/\n|\r\n?/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const eqPos = trimmed.indexOf('=');
    if (eqPos < 0) continue;
    const name = trimmed.substring(0, eqPos).trim();
    const value = trimmed.substring(eqPos + 1).trim();
    const parts = value.split(',').map(s => s.trim());
    if (parts.length < 3) continue;

    const type = parts[0];
    const server = parts[1].includes(':') ? parts[1].substring(0, parts[1].lastIndexOf(':')) : parts[1];
    const port = parts[1].includes(':') ? parts[1].substring(parts[1].lastIndexOf(':') + 1) : parts[2];

    if (!server || !port || port === '0') continue;

    switch (type) {
      case 'vmess': {
        const node = parseVMessQuan(`${name} = vmess,${parts.slice(1).join(',')}`);
        if (node) nodes.push(node);
        break;
      }
      case 'ss':
      case 'shadowsocks': {
        let method = '', password = '', protocol = '', obfs = '', obfsHost = '', path = '',
          udp = false, tfo = false, tls = '';
        for (let i = 2; i < parts.length; i++) {
          const kv = parts[i].split('=');
          if (kv.length < 2) continue;
          switch (kv[0].trim()) {
            case 'method': method = kv[1].trim(); break;
            case 'password': password = kv[1].trim(); break;
            case 'ssr-protocol': protocol = kv[1].trim(); break;
            case 'obfs':
              switch (kv[1].trim()) {
                case 'http': case 'tls': obfs = 'simple-obfs'; obfsHost = kv[1].trim(); break;
                case 'ws': case 'wss': obfs = 'v2ray-plugin'; break;
                default: obfs = kv[1].trim();
              }
              break;
            case 'obfs-host': obfsHost = kv[1].trim(); break;
            case 'obfs-uri': path = kv[1].trim(); break;
            case 'udp-relay': udp = kv[1].trim() === 'true'; break;
            case 'fast-open': tfo = kv[1].trim() === 'true'; break;
            case 'tag': name.replace(name, kv[1].trim()); break;
          }
        }
        if (protocol) {
          nodes.push(buildNode('ssr', server, port, { name, cipher: method, password, protocol, obfs: obfsHost }));
        } else {
          nodes.push(buildNode('ss', server, port, { name, cipher: method, password, plugin: obfs, pluginOpts: obfsHost, udp, tfo }));
        }
        break;
      }
      case 'trojan': {
        let password = '', sni = '', udp = false, scv = false;
        for (let i = 2; i < parts.length; i++) {
          const kv = parts[i].split('=');
          if (kv.length < 2) continue;
          switch (kv[0].trim()) {
            case 'password': password = kv[1].trim(); break;
            case 'tls-host': sni = kv[1].trim(); break;
            case 'udp-relay': udp = kv[1].trim() === 'true'; break;
            case 'tls-verification': scv = kv[1].trim() === 'false'; break;
          }
        }
        nodes.push(buildNode('trojan', server, port, { name, password, sni: sni || server, udp, skipCertVerify: scv }));
        break;
      }
    }
  }
  return nodes;
}

// ═══════════════════════════════════════════════════════════
//  导出
// ═══════════════════════════════════════════════════════════

module.exports = {
  parseNode,
  parseSubscription,
  // 各协议独立解析器（用于调试）
  parseSS, parseSSR, parseVMess, parseTrojan, parseVLESS,
  parseHysteria, parseHysteria2, parseTUIC, parseAnyTLS,
  parseSOCKS, parseHTTP,
  parseClashYAML, parseSurgeConf,
  parseSSD, parseSingboxOutbounds,
  // 工具函数
  urlSafeBase64Decode, getUrlArg
};
