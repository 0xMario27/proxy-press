/**
 * ProxyPress Worker v5 — parser 与本地 sub-converter-parser.js 同步
 */

/**
 * sub-converter-parser.js
 * 
 * JS 版订阅链接解析器 —— 对标 C++ subconverter 的 subparser.cpp
 * 
 * 支持的协议:
 *   vmess:// | ss:// | ssr:// | trojan:// | vless:// 
 *   hysteria:// | hy:// | hysteria2:// | hy2:// | tuic:// | anytls://
 *   socks:// | http:// | https:// | clash YAML | surge conf
 */

// ═══════════════════════════════════════════════════════════
//  工具函数
// ═══════════════════════════════════════════════════════════

function urlSafeBase64Decode(str) {
  if (!str) return '';
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  try {
    return atob(str);
  } catch {
    return str;
  }
}

function getUrlArg(query, key) {
  if (!query) return '';
  const regex = new RegExp('[?&]' + encodeURIComponent(key) + '=([^&]*)');
  const m = query.match(regex);
  return m ? decodeURIComponent(m[1]) : '';
}

function extractRemark(uri) {
  let remark = '';
  const hashPos = uri.lastIndexOf('#');
  if (hashPos > 0) {
    remark = decodeURIComponent(uri.substring(hashPos + 1));
    uri = uri.substring(0, hashPos);
  }
  const midHash = uri.indexOf('#');
  if (midHash > 0) uri = uri.substring(0, midHash);
  return { uri, remark };
}

function getAlpnList(query) {
  const raw = getUrlArg(query, 'alpn');
  if (!raw) return [];
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

function unbracket(host) {
  if (host.startsWith('[') && host.endsWith(']')) return host.slice(1, -1);
  return host;
}

function buildNode(type, server, port, extras) {
  if (!extras) extras = {};
  const name = extras.name || extras.remarks || (server + ':' + port);
  return Object.assign({ type: type, name: name, server: unbracket(server), port: parseInt(port) || port }, extras);
}

const SS_CIPHERS = new Set([
  'rc4-md5','aes-128-gcm','aes-192-gcm','aes-256-gcm',
  'aes-128-cfb','aes-192-cfb','aes-256-cfb',
  'aes-128-ctr','aes-192-ctr','aes-256-ctr',
  'camellia-128-cfb','camellia-192-cfb','camellia-256-cfb',
  'bf-cfb','chacha20-ietf-poly1305','xchacha20-ietf-poly1305',
  'salsa20','chacha20','chacha20-ietf',
  '2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305','2022-blake3-chacha12-poly1305',
  '2022-blake3-chacha8-poly1305'
]);

// ═══════════════════════════════════════════════════════════
//  SS (ss://)
// ═══════════════════════════════════════════════════════════

function parseSS(uri) {
  if (!uri.startsWith('ss://')) return null;
  var rest = uri.slice(5).replace('/?', '?');
  var ext = extractRemark(rest);
  rest = ext.uri;
  var remark = ext.remark;

  var qPos = rest.indexOf('?');
  var addition = qPos > 0 ? rest.substring(qPos + 1) : '';
  if (qPos > 0) rest = rest.substring(0, qPos);

  var password, method, server, port;
  var plugin = '', pluginOpts = '';

  if (rest.includes('@')) {
    // SIP002: userinfo@host:port  (userinfo may be base64(method:password) or raw method:password)
    var atPos = rest.lastIndexOf('@');
    var userinfo = rest.substring(0, atPos);
    var hostpart = rest.substring(atPos + 1);

    // Try base64 decode the userinfo
    var decodedUserinfo = urlSafeBase64Decode(userinfo);
    if (decodedUserinfo.includes(':')) {
      var cPos = decodedUserinfo.indexOf(':');
      method = decodedUserinfo.substring(0, cPos);
      password = decodedUserinfo.substring(cPos + 1);
    } else {
      // Raw method:password
      var cPos = userinfo.indexOf(':');
      if (cPos < 0) return null;
      method = userinfo.substring(0, cPos);
      password = userinfo.substring(cPos + 1);
    }

    var hColon = hostpart.lastIndexOf(':');
    if (hColon > 0) {
      server = hostpart.substring(0, hColon);
      port = hostpart.substring(hColon + 1);
    } else {
      server = hostpart;
      port = '8388';
    }
  } else {
    // Legacy base64: base64(method:password@server:port)
    var decoded = urlSafeBase64Decode(rest);
    var m = decoded.match(/^(.+):(.+)@(.+):(\d+)$/);
    if (!m) return null;
    method = m[1]; password = m[2]; server = m[3]; port = m[4];
  }

  if (!server || !port || port === '0') return null;

  var rawPlugin = getUrlArg(addition, 'plugin');
  if (rawPlugin) {
    var semiPos = rawPlugin.indexOf(';');
    plugin = semiPos > 0 ? rawPlugin.substring(0, semiPos) : rawPlugin;
    pluginOpts = semiPos > 0 ? rawPlugin.substring(semiPos + 1) : '';
  }

  var name = remark || (server + ':' + port);
  var group = getUrlArg(addition, 'group');
  return buildNode('ss', server, port, {
    name: group ? (group + ' - ' + name) : name,
    password: password, cipher: method,
    plugin: plugin, pluginOpts: pluginOpts,
    udp: getUrlArg(addition, 'udp') !== '0'
  });
}

// ═══════════════════════════════════════════════════════════
//  SSR (ssr://)
// ═══════════════════════════════════════════════════════════

function parseSSR(uri) {
  if (!uri.startsWith('ssr://')) return null;
  var rest = uri.slice(6).replace(/\r/g, '');
  var decoded = urlSafeBase64Decode(rest);

  var obfsParam = '', protoParam = '', group = '', remarks = '';
  var obfsPos = decoded.indexOf('/?');
  if (obfsPos > 0) {
    var obfsStr = decoded.substring(obfsPos + 2);
    decoded = decoded.substring(0, obfsPos);
    group = urlSafeBase64Decode(getUrlArg(obfsStr, 'group'));
    remarks = urlSafeBase64Decode(getUrlArg(obfsStr, 'remarks'));
    obfsParam = urlSafeBase64Decode(getUrlArg(obfsStr, 'obfsparam')).replace(/\s/g, '');
    protoParam = urlSafeBase64Decode(getUrlArg(obfsStr, 'protoparam')).replace(/\s/g, '');
  }

  var parts = decoded.split(':');
  if (parts.length < 6) return null;
  var server = parts[0], port = parts[1], protocol = parts[2],
      method = parts[3], obfs = parts[4], password = urlSafeBase64Decode(parts[5]);

  if (!server || !port || port === '0') return null;

  var name = remarks || (server + ':' + port);
  var grp = group || 'SSRProvider';

  if (SS_CIPHERS.has(method) && (!obfs || obfs === 'plain') && (!protocol || protocol === 'origin')) {
    return buildNode('ss', server, port, {
      name: grp + ' - ' + name, password: password, cipher: method, plugin: '', pluginOpts: ''
    });
  }

  return buildNode('ssr', server, port, {
    name: grp + ' - ' + name, password: password, cipher: method,
    protocol: protocol, obfs: obfs,
    protocolParam: protoParam, obfsParam: obfsParam
  });
}

// ═══════════════════════════════════════════════════════════
//  VMess (vmess://)
// ═══════════════════════════════════════════════════════════

function parseVMess(uri) {
  if (!uri.startsWith('vmess://') && !uri.startsWith('vmess1://')) return null;

  // Shadowrocket style: vmess://base64?params
  if (/^vmess:\/\/[A-Za-z0-9+\/\-_=]+\?/.test(uri)) return parseVMessShadowrocket(uri);
  // Standard style: vmess://net+tls:uuid-aid@host:port/?params
  if (/^vmess:\/\/[a-z]+\+?[a-z]*:[\da-f]{8}-/.test(uri)) return parseVMessStandard(uri);
  // Kitsunebi style
  if (uri.startsWith('vmess1://')) return parseVMessKitsunebi(uri);

  // JSON / Quantumult X style
  var b64 = uri.replace(/^(vmess|vmess1):\/\//, '');
  var decoded = urlSafeBase64Decode(b64);

  if (decoded.includes(' = ')) return parseVMessQuan(decoded);

  try {
    var json = JSON.parse(decoded);
    if (json.add && json.port) return parseVMessJson(json);
  } catch(e) {}

  return null;
}

function parseVMessJson(json) {
  var version = json.v || '1';
  var ps = json.ps || '';
  var add = (json.add || '').trim();
  var port = String(json.port);
  if (port === '0' || !port) return null;

  var id = json.id || '';
  var aid = json.aid || '0';
  var net = json.net || 'tcp';
  var tlsVal = json.tls || '';
  var host = json.host || '';
  var path = '', sni = json.sni || '';

  if (version === '1') {
    if (host) { var vArr = host.split(';'); if (vArr.length === 2) { host = vArr[0]; path = vArr[1]; } }
  } else {
    path = json.path || '';
  }

  return buildNode('vmess', add, port, {
    name: ps || (add + ':' + port),
    uuid: id || '00000000-0000-0000-0000-000000000000',
    alterId: parseInt(aid) || 0,
    cipher: json.scy || 'auto',
    network: net,
    tls: tlsVal === 'tls' ? 'tls' : 'none',
    host: host, path: path, sni: sni
  });
}

function parseVMessShadowrocket(uri) {
  uri = uri.slice(8);
  var qPos = uri.indexOf('?');
  var addition = qPos > 0 ? uri.substring(qPos + 1) : '';
  var encoded = qPos > 0 ? uri.substring(0, qPos) : uri;
  var decoded = urlSafeBase64Decode(encoded);
  var m = decoded.match(/^(.+):(.+)@(.+):(\d+)$/);
  if (!m) return null;
  var cipher = m[1], id = m[2], server = m[3], port = m[4];
  if (port === '0') return null;

  var remarks = decodeURIComponent(getUrlArg(addition, 'remarks'));
  var obfs = getUrlArg(addition, 'obfs');
  var network = 'tcp', host = '', path = '';
  if (obfs) {
    if (obfs === 'websocket') { network = 'ws'; host = getUrlArg(addition, 'obfsParam'); path = getUrlArg(addition, 'path'); }
  } else {
    network = getUrlArg(addition, 'network') || 'tcp';
    host = getUrlArg(addition, 'wsHost') || '';
    path = getUrlArg(addition, 'wspath') || '';
  }
  var tlsVal = getUrlArg(addition, 'tls') === '1' ? 'tls' : 'none';
  var aid = getUrlArg(addition, 'aid') || '0';
  return buildNode('vmess', server, port, {
    name: remarks || (server + ':' + port),
    uuid: id, alterId: parseInt(aid) || 0, cipher: cipher || 'auto',
    network: network, tls: tlsVal, host: host, path: path
  });
}

function parseVMessStandard(uri) {
  uri = uri.slice(8);
  var ext = extractRemark(uri);
  var cleaned = ext.uri, remark = ext.remark;
  var m = cleaned.match(/^([a-z]+)(?:\+([a-z]+))?:([\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12})-(\d+)@(.+):(\d+)(?:\/?(.*))?$/i);
  if (!m) return null;
  var net = m[1], tlsType = m[2] || '', uuid = m[3], aid = m[4], server = m[5], port = m[6], addition = m[7] || '';
  var host = '', path = '';
  switch (net) {
    case 'ws': case 'http': host = getUrlArg(addition, 'host'); path = getUrlArg(addition, 'path'); break;
    case 'quic': host = getUrlArg(addition, 'type'); path = getUrlArg(addition, 'key'); break;
  }
  return buildNode('vmess', server, port, {
    name: remark || (server + ':' + port),
    uuid: uuid, alterId: parseInt(aid) || 0, cipher: 'auto',
    network: net, tls: tlsType === 'tls' ? 'tls' : 'none', host: host, path: path
  });
}

function parseVMessKitsunebi(uri) {
  uri = uri.slice(9);
  var ext = extractRemark(uri);
  var cleaned = ext.uri, remark = ext.remark;
  var qPos = cleaned.indexOf('?');
  var addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  var base = qPos > 0 ? cleaned.substring(0, qPos) : cleaned;
  var m = base.match(/^(.+)@(.+):(\d+)(\/.*)?$/);
  if (!m) return null;
  var id = m[1], server = m[2], port = m[3], path = m[4] || '';
  if (port === '0') return null;
  var network = getUrlArg(addition, 'network') || 'tcp';
  var tlsVal = getUrlArg(addition, 'tls') === 'true' ? 'tls' : 'none';
  var host = getUrlArg(addition, 'ws.host') || '';
  return buildNode('vmess', server, port, {
    name: remark || (server + ':' + port),
    uuid: id, alterId: 0, cipher: 'auto',
    network: network, tls: tlsVal, host: host, path: path
  });
}

function parseVMessQuan(str) {
  var m = str.match(/^(.*?) = vmess,(.*)$/);
  if (!m) return null;
  var ps = m[1].trim();
  var configs = m[2].split(',');
  if (configs.length < 4) return null;
  var add = configs[0].trim();
  var port = configs[1].trim();
  if (port === '0') return null;
  var cipher = configs[2].trim();
  var id = configs[3].trim().replace(/"/g, '');
  var group = 'V2RayProvider', tls = 'none', host = '', path = '/', network = 'tcp';

  for (var i = 4; i < configs.length; i++) {
    var eqPos = configs[i].indexOf('=');
    if (eqPos < 0) continue;
    var key = configs[i].substring(0, eqPos).trim();
    var val = configs[i].substring(eqPos + 1).trim();
    if (key === 'group') group = val;
    else if (key === 'over-tls') tls = val === 'true' ? 'tls' : 'none';
    else if (key === 'tls-host') host = val;
    else if (key === 'obfs-path') path = val.replace(/"/g, '');
    else if (key === 'obfs' && val === 'ws') network = 'ws';
  }
  return buildNode('vmess', add, port, {
    name: group + ' - ' + ps, uuid: id, alterId: 0, cipher: cipher,
    network: network, tls: tls, host: host, path: path
  });
}

// ═══════════════════════════════════════════════════════════
//  Trojan (trojan://)
// ═══════════════════════════════════════════════════════════

function parseTrojan(uri) {
  if (!uri.startsWith('trojan://') && !uri.startsWith('trojan-go://')) return null;
  uri = uri.replace(/^trojan-go:\/\//, 'trojan://');
  var rest = uri.slice(9);
  var ext = extractRemark(rest);
  var cleaned = ext.uri, remark = ext.remark;
  var qPos = cleaned.indexOf('?');
  var addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  var base = qPos > 0 ? cleaned.substring(0, qPos) : cleaned;
  var m = base.match(/^(.+)@(.+):(\d+)$/);
  if (!m) return null;
  var password = m[1], server = m[2], port = m[3];
  if (port === '0') return null;

  var sni = getUrlArg(addition, 'sni');
  var host = getUrlArg(addition, 'host') || sni;
  if (!host) host = getUrlArg(addition, 'peer');
  var fp = getUrlArg(addition, 'fp');
  var scv = getUrlArg(addition, 'allowInsecure');
  var group = decodeURIComponent(getUrlArg(addition, 'group'));
  var network = 'tcp', path = '';

  if (getUrlArg(addition, 'ws') === '1') { path = getUrlArg(addition, 'wspath'); network = 'ws'; }
  else if (getUrlArg(addition, 'type') === 'ws') {
    path = getUrlArg(addition, 'path');
    if (path.substring(0, 3) === '%2F') path = decodeURIComponent(path);
    network = 'ws';
  } else if (getUrlArg(addition, 'type') === 'grpc') { path = getUrlArg(addition, 'serviceName'); network = 'grpc'; }

  var name = remark || (server + ':' + port);
  return buildNode('trojan', server, port, {
    name: group ? (group + ' - ' + name) : name,
    password: password, sni: sni || host || server, host: host, network: network, path: path,
    fingerprint: fp || 'chrome',
    skipCertVerify: scv === '1' || scv === 'true',
    udp: true
  });
}

// ═══════════════════════════════════════════════════════════
//  VLESS (vless://)
// ═══════════════════════════════════════════════════════════

function parseVLESS(uri) {
  if (!uri.startsWith('vless://') && !uri.startsWith('vless1://')) return null;
  var rest = uri.replace(/^vless1?:\/\//, '');
  var ext = extractRemark(rest);
  var cleaned = ext.uri, remark = ext.remark;
  var qPos = cleaned.indexOf('?');
  var addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  var m = cleaned.match(/^([\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12})@\[?([\d\-a-zA-Z:.]+)\]?:(\d+)(?:\/?(.*))?$/);
  if (!m) return null;
  var id = m[1], server = m[2], port = m[3];
  if (!server || !port || port === '0') return null;

  var tlsVal = getUrlArg(addition, 'security') || 'none';
  var net = getUrlArg(addition, 'type') || 'tcp';
  var flow = getUrlArg(addition, 'flow');
  var pbk = getUrlArg(addition, 'pbk');
  var sid = getUrlArg(addition, 'sid');
  var encryption = getUrlArg(addition, 'encryption');
  var fp = getUrlArg(addition, 'fp') || 'chrome';
  var sni = getUrlArg(addition, 'sni');
  var host = '', path = '';

  switch (net) {
    case 'tcp': case 'http': case 'ws': case 'h2':
      host = getUrlArg(addition, addition.indexOf('sni') >= 0 ? 'sni' : 'host');
      path = getUrlArg(addition, 'path');
      break;
    case 'grpc':
      host = getUrlArg(addition, 'sni');
      path = getUrlArg(addition, 'serviceName');
      break;
    case 'quic':
      host = getUrlArg(addition, addition.indexOf('sni') >= 0 ? 'sni' : 'quicSecurity');
      path = getUrlArg(addition, 'key');
      break;
    case 'xhttp':
      host = getUrlArg(addition, addition.indexOf('sni') >= 0 ? 'sni' : 'host');
      path = getUrlArg(addition, 'path');
      break;
  }
  if (!sni) sni = host;

  return buildNode('vless', server, port, {
    name: remark || (server + ':' + port),
    uuid: id, alterId: 0, cipher: 'auto',
    network: net, tls: tlsVal, flow: flow,
    fingerprint: fp, publicKey: pbk, shortId: sid,
    encryption: encryption, sni: sni, host: host, path: path,
    alpn: getAlpnList(addition)
  });
}

// ═══════════════════════════════════════════════════════════
//  Hysteria / Hysteria2 / TUIC / AnyTLS / SOCKS5 / HTTP
// ═══════════════════════════════════════════════════════════

function parseHysteria(uri) {
  if (!uri.startsWith('hysteria://') && !uri.startsWith('hy://')) return null;
  uri = uri.replace(/^hy:\/\//, 'hysteria://');
  var rest = uri.slice(11);
  var ext = extractRemark(rest);
  var cleaned = ext.uri, remark = ext.remark;
  var qPos = cleaned.indexOf('?');
  var addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  var m = cleaned.match(/^(.+):(\d+)\?(.*)$/);
  if (!m) return null;
  var server = m[1], port = m[2], extra = m[3] + '&' + addition;

  return buildNode('hysteria', server, port, {
    name: remark || (server + ':' + port),
    auth: getUrlArg(extra, 'auth') || getUrlArg(extra, 'auth_str') || '',
    peer: getUrlArg(extra, 'peer') || server,
    insecure: getUrlArg(extra, 'insecure') === '1',
    upMbps: getUrlArg(extra, 'upmbps'),
    downMbps: getUrlArg(extra, 'downmbps'),
    alpn: getAlpnList(extra).join(','),
    obfs: getUrlArg(extra, 'obfsParam') || '',
    sni: getUrlArg(extra, 'peer') || server,
    udp: true
  });
}

function parseHysteria2(uri) {
  if (!uri.startsWith('hysteria2://') && !uri.startsWith('hy2://')) return null;
  uri = uri.replace(/^hy2:\/\//, 'hysteria2://');
  var rest = uri.slice(12).replace('/?', '?');
  var ext = extractRemark(rest);
  var cleaned = ext.uri, remark = ext.remark;
  var qPos = cleaned.indexOf('?');
  var addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  var base = qPos > 0 ? cleaned.substring(0, qPos) : cleaned;

  var password, server, port;
  if (base.includes('@')) {
    var m = base.match(/^(.+)@(.+):(\d+)$/);
    if (!m) return null;
    password = m[1]; server = m[2]; port = m[3];
  } else {
    var m = base.match(/^(.+):(\d+)$/);
    if (!m) return null;
    server = m[1]; port = m[2];
    password = getUrlArg(addition, 'password');
  }
  if (!server || !port || port === '0') return null;

  return buildNode('hysteria2', server, port, {
    name: remark || (server + ':' + port),
    password: password || '',
    sni: getUrlArg(addition, 'sni') || server,
    skipCertVerify: getUrlArg(addition, 'insecure') === '1',
    upMbps: getUrlArg(addition, 'up'),
    downMbps: getUrlArg(addition, 'down'),
    alpn: getAlpnList(addition).join(','),
    obfs: getUrlArg(addition, 'obfs') || '',
    obfsPassword: getUrlArg(addition, 'obfs-password') || '',
    ports: getUrlArg(addition, 'ports') || '',
    udp: true
  });
}

function parseTUIC(uri) {
  if (!uri.startsWith('tuic://')) return null;
  var rest = uri.slice(7);
  var ext = extractRemark(rest);
  var cleaned = ext.uri, remark = ext.remark;
  var qPos = cleaned.indexOf('?');
  var addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  var base = qPos > 0 ? cleaned.substring(0, qPos) : cleaned;
  var m = base.match(/^([^:]+):(.+)@(.+):(\d+)$/);
  if (!m) return null;
  var uuid = m[1], password = m[2], server = m[3], port = m[4];
  if (!server || !port || port === '0') return null;

  return buildNode('tuic', server, port, {
    name: remark || (server + ':' + port),
    uuid: uuid, password: password,
    sni: getUrlArg(addition, 'sni') || server,
    alpn: getAlpnList(addition).join(','),
    congestionControl: getUrlArg(addition, 'congestion_control') || 'bbr',
    skipCertVerify: getUrlArg(addition, 'insecure') === '1',
    udp: true
  });
}

function parseAnyTLS(uri) {
  if (!uri.startsWith('anytls://')) return null;
  var rest = uri.slice(9);
  var ext = extractRemark(rest);
  var cleaned = ext.uri, remark = ext.remark;
  var qPos = cleaned.indexOf('?');
  var addition = qPos > 0 ? cleaned.substring(qPos + 1) : '';
  var base = qPos > 0 ? cleaned.substring(0, qPos) : cleaned;

  var atPos = base.indexOf('@');
  if (atPos < 0) return null;
  var password = base.substring(0, atPos);
  var hostPart = base.substring(atPos + 1);
  var colonPos = hostPart.lastIndexOf(':');
  if (colonPos < 0) return null;
  var server = hostPart.substring(0, colonPos);
  var port = hostPart.substring(colonPos + 1);
  if (!server || !port || port === '0') return null;

  var fp = getUrlArg(addition, 'fp') || getUrlArg(addition, 'fingerprint') || '';
  if (!fp) fp = decodeURIComponent(getUrlArg(addition, 'hpkp') || '');
  var sni = getUrlArg(addition, 'sni') || getUrlArg(addition, 'peer') || server;

  return buildNode('anytls', server, port, {
    name: remark || (server + ':' + port),
    password: password, sni: sni, fingerprint: fp || 'chrome',
    alpn: getAlpnList(addition),
    skipCertVerify: getUrlArg(addition, 'insecure') === '1',
    udp: getUrlArg(addition, 'udp') !== '0'
  });
}

function parseSOCKS(uri) {
  if (uri.startsWith('socks://')) {
    var rest = uri.slice(8);
    var ext = extractRemark(rest);
    var cleaned = ext.uri, remark = ext.remark;
    var decoded = urlSafeBase64Decode(cleaned);
    var username = '', password = '', server, port;
    if (decoded.includes('@')) {
      var parts = decoded.split('@');
      decoded = parts[1];
      var userinfo = parts[0].split(':');
      if (userinfo.length >= 2) { username = userinfo[0]; password = userinfo[1]; }
    }
    var hp = decoded.split(':');
    if (hp.length < 2) return null;
    server = hp[0]; port = hp[1];
    if (port === '0') return null;
    return buildNode('socks5', server, port, { name: remark || (server + ':' + port), username: username, password: password });
  }
  if (uri.includes('t.me/socks') || uri.startsWith('tg://socks')) {
    var server = getUrlArg(uri, 'server'), port = getUrlArg(uri, 'port');
    if (!server || !port || port === '0') return null;
    return buildNode('socks5', server, port, {
      name: decodeURIComponent(getUrlArg(uri, 'remarks')) || (server + ':' + port),
      username: decodeURIComponent(getUrlArg(uri, 'user')),
      password: decodeURIComponent(getUrlArg(uri, 'pass'))
    });
  }
  return null;
}

function parseHTTP(uri) {
  if (uri.includes('t.me/http') || uri.startsWith('tg://http')) {
    var server = getUrlArg(uri, 'server'), port = getUrlArg(uri, 'port');
    if (!server || !port || port === '0') return null;
    var isTLS = uri.includes('/https');
    return buildNode(isTLS ? 'https' : 'http', server, port, {
      name: decodeURIComponent(getUrlArg(uri, 'remarks')) || (server + ':' + port),
      username: decodeURIComponent(getUrlArg(uri, 'user')),
      password: decodeURIComponent(getUrlArg(uri, 'pass')),
      tls: isTLS
    });
  }
  return null;
}

// ═══════════════════════════════════════════════════════════
//  Clash YAML / Surge / SS-D / Sing-box
// ═══════════════════════════════════════════════════════════

function parseClashYAML(content) {
  var nodes = [];
  // 逐行解析 proxies 块
  var lines = content.split('\n');
  var inProxy = false, current = [], entries = [];
  for (var li = 0; li < lines.length; li++) {
    var line = lines[li];
    if (/^(?:Proxy|proxies):/.test(line)) { inProxy = true; continue; }
    if (!inProxy) continue;
    // 下一个顶级 key 或空行后的 key 结束 proxy 块
    if (/^[a-zA-Z]/.test(line) && !/^\s/.test(line)) { inProxy = false; continue; }
    if (/^\s+- /.test(line)) {
      if (current.length > 0) entries.push(current.join('\n'));
      current = [line];
    } else if (/^\s+\S/.test(line)) {
      current.push(line);
    }
  }
  if (current.length > 0) entries.push(current.join('\n'));
  for (var i = 0; i < entries.length; i++) {
    var proxy = parseClashProxyEntry(entries[i].trim());
    if (proxy) nodes.push(proxy);
  }
  return nodes;
}

function parseClashProxyEntry(entry) {
  // 去掉前导空白和 "- " 标记
  entry = entry.replace(/^\s*-\s*/, '');
  // 兼容 flow 风格: {name: SS-1, type: ss, server: s1.com, ...}
  var flowMatch = entry.match(/^\{(.+)\}$/);
  if (flowMatch) {
    var fields = {};
    var pairs = flowMatch[1].split(/,(?=(?:[^']*'[^']*')*[^']*$)(?=(?:[^"]*"[^"]*")*[^"]*$)/);
    for (var pi = 0; pi < pairs.length; pi++) {
      var kv = pairs[pi].split(':');
      if (kv.length >= 2) {
        var k = kv[0].trim().replace(/^['"]|['"]$/g, '');
        var v = kv.slice(1).join(':').trim().replace(/^['"]|['"]$/g, '');
        fields[k] = v;
      }
    }
    return buildClashNode(fields);
  }

  var fields = {};
  var lines = entry.split('\n');
  var currentKey = '';
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var kvMatch = line.match(/^\s*(?:- )?(\S[^:]*?):\s*(.*)/);
    if (kvMatch) { currentKey = kvMatch[1].trim(); fields[currentKey] = kvMatch[2].trim(); }
    else {
      var mvMatch = line.match(/^\s+-\s+(.*)/);
      if (mvMatch) { if (!Array.isArray(fields[currentKey])) fields[currentKey] = []; fields[currentKey].push(mvMatch[1].trim()); }
    }
  }
  return buildClashNode(fields);
}

function buildClashNode(fields) {
  var type = fields.type, server = fields.server, port = fields.port || '0';
  if (!type || !server || port === '0') return null;
  var base = { name: fields.name || '', server: unbracket(server), port: parseInt(port) };
  switch (type) {
    case 'ss': return Object.assign({ type: 'ss' }, base, { cipher: fields.cipher || '', password: fields.password || '', plugin: fields.plugin || '', pluginOpts: fields['plugin-opts'] || '' });
    case 'ssr': return Object.assign({ type: 'ssr' }, base, { cipher: fields.cipher || '', password: fields.password || '', protocol: fields.protocol || 'origin', obfs: fields.obfs || 'plain' });
    case 'vmess': return Object.assign({ type: 'vmess' }, base, { uuid: fields.uuid || '', alterId: parseInt(fields.alterId) || 0, cipher: fields.cipher || 'auto', network: fields.network || 'tcp', tls: fields.tls === 'true' ? 'tls' : 'none', sni: fields.servername || '' });
    case 'trojan': return Object.assign({ type: 'trojan' }, base, { password: fields.password || '', sni: fields.sni || server, network: fields.network || 'tcp' });
    case 'vless': return Object.assign({ type: 'vless' }, base, { uuid: fields.uuid || '', network: fields.network || 'tcp', tls: fields.tls === 'true' ? 'tls' : 'none', sni: fields.sni || fields.servername || '' });
    case 'hysteria': return Object.assign({ type: 'hysteria' }, base, { auth: fields['auth-str'] || fields.auth_str || fields.password || '', upMbps: fields.up || '', downMbps: fields.down || '', sni: fields.sni || server });
    case 'hysteria2': return Object.assign({ type: 'hysteria2' }, base, { password: fields.password || fields.auth || '', upMbps: fields.up || '', downMbps: fields.down || '', sni: fields.sni || server });
    case 'tuic': return Object.assign({ type: 'tuic' }, base, { password: fields.password || '', uuid: fields.uuid || '', sni: fields.sni || server, congestionControl: fields['congestion-controller'] || 'bbr' });
    case 'http': return Object.assign({ type: 'http' }, base, { username: fields.username || '', password: fields.password || '', tls: fields.tls === 'true' });
    case 'socks5': return Object.assign({ type: 'socks5' }, base, { username: fields.username || '', password: fields.password || '' });
    default: return null;
  }
}

function parseSurgeConf(content) {
  var nodes = [];
  var pm = content.match(/\[Proxy\]\r?\n([\s\S]*?)(?:\r?\n\[|$)/);
  if (!pm) return nodes;
  var lines = pm[1].split('\n');
  for (var i = 0; i < lines.length; i++) {
    var trimmed = lines[i].trim();
    if (!trimmed || trimmed[0] === ';' || trimmed[0] === '#' || trimmed.startsWith('//')) continue;
    var eqPos = trimmed.indexOf('=');
    if (eqPos < 0) continue;
    var name = trimmed.substring(0, eqPos).trim();
    var value = trimmed.substring(eqPos + 1).trim();
    var parts = value.split(',').map(function(s) { return s.trim(); });
    if (parts.length < 3) continue;
    var type = parts[0], server = parts[1], port = parts[2];
    if (port === '0') continue;

    if (type === 'ss' || type === 'custom') {
      var method = '', password = '', obfs = '', obfsHost = '', udp = false;
      for (var j = (type === 'custom' ? 3 : 3); j < parts.length; j++) {
        var kv = parts[j].split('='); if (kv.length < 2) continue;
        var k = kv[0].trim(), v = kv[1].trim();
        if (k === 'encrypt-method' || (type === 'custom' && j === 3)) method = v;
        else if (k === 'password' || (type === 'custom' && j === 4)) password = v;
        else if (k === 'obfs') obfs = v;
        else if (k === 'obfs-host') obfsHost = v;
        else if (k === 'udp-relay') udp = v === 'true';
      }
      if (type === 'custom' && parts.length >= 5) { method = parts[3]; password = parts[4]; }
      nodes.push(buildNode('ss', server, port, { name: name, cipher: method, password: password, plugin: obfs ? 'obfs-local' : '', pluginOpts: obfs ? ('obfs=' + obfs + (obfsHost ? ';obfs-host=' + obfsHost : '')) : '', udp: udp }));
    } else if (type === 'vmess') {
      var id = '', ws = 'tcp', tls = 'none', path = '/', host = '';
      for (var j = 3; j < parts.length; j++) {
        var kv = parts[j].split('='); if (kv.length < 2) continue;
        var k = kv[0].trim(), v = kv[1].trim();
        if (k === 'username') id = v;
        else if (k === 'ws') ws = v === 'true' ? 'ws' : 'tcp';
        else if (k === 'tls') tls = v === 'true' ? 'tls' : 'none';
        else if (k === 'ws-path') path = v;
        else if (k === 'obfs-host') host = v;
      }
      nodes.push(buildNode('vmess', server, port, { name: name, uuid: id, alterId: 0, cipher: 'auto', network: ws, tls: tls, host: host, path: path }));
    } else if (type === 'trojan') {
      var password = '', sni = '';
      for (var j = 3; j < parts.length; j++) {
        var kv = parts[j].split('='); if (kv.length < 2) continue;
        if (kv[0].trim() === 'password') password = kv[1].trim();
        else if (kv[0].trim() === 'sni') sni = kv[1].trim();
      }
      nodes.push(buildNode('trojan', server, port, { name: name, password: password, sni: sni || server, udp: true }));
    } else if (type === 'http') {
      var username = '', password = '';
      for (var j = 3; j < parts.length; j++) {
        var kv = parts[j].split('='); if (kv.length < 2) continue;
        if (kv[0].trim() === 'username') username = kv[1].trim();
        else if (kv[0].trim() === 'password') password = kv[1].trim();
      }
      nodes.push(buildNode('http', server, port, { name: name, username: username, password: password }));
    } else if (type === 'socks5') {
      nodes.push(buildNode('socks5', server, port, { name: name, username: parts[3] || '', password: parts[4] || '' }));
    }
  }
  return nodes;
}

function parseSSD(uri) {
  var b64 = uri.slice(6);
  var decoded = urlSafeBase64Decode(b64);
  var json;
  try { json = JSON.parse(decoded); } catch(e) { return []; }
  if (!json.servers) return [];
  var group = json.airport || '';
  var defPort = json.port || '', defMethod = json.encryption || '', defPassword = json.password || '';
  var defPlugin = json.plugin || '', defPluginOpts = json.plugin_options || '';
  var nodes = [];
  var serverList = Array.isArray(json.servers) ? json.servers : Object.values(json.servers);
  for (var i = 0; i < serverList.length; i++) {
    var s = serverList[i];
    var server = s.server || '', port = s.port || defPort;
    if (!server || !port || port === '0') continue;
    nodes.push(buildNode('ss', server, port, {
      name: group ? (group + ' - ' + (s.remarks || (server + ':' + port))) : (s.remarks || (server + ':' + port)),
      cipher: s.encryption || defMethod,
      password: s.password || defPassword,
      plugin: s.plugin || defPlugin,
      pluginOpts: s.plugin_options || defPluginOpts
    }));
  }
  return nodes;
}

function parseSingboxOutbounds(outbounds) {
  if (!Array.isArray(outbounds)) return [];
  var nodes = [];
  for (var i = 0; i < outbounds.length; i++) {
    var item = outbounds[i];
    if (!item || !item.type) continue;
    var server = item.server || '', port = parseInt(item.server_port) || 0;
    if (!server || !port) continue;
    var tlsObj = item.tls || {};
    var tlsEnabled = tlsObj.enabled === true;
    var sni = tlsObj.server_name || '';
    var base = { name: item.tag || '', server: unbracket(server), port: port };
    switch (item.type) {
      case 'vmess': nodes.push(Object.assign({ type: 'vmess' }, base, { uuid: item.uuid || '', alterId: parseInt(item.alter_id) || 0, cipher: item.security || 'auto', network: (item.transport && item.transport.type) || 'tcp', tls: tlsEnabled ? 'tls' : 'none', sni: sni })); break;
      case 'shadowsocks': nodes.push(Object.assign({ type: 'ss' }, base, { cipher: item.method || '', password: item.password || '' })); break;
      case 'trojan': nodes.push(Object.assign({ type: 'trojan' }, base, { password: item.password || '', sni: sni, network: (item.transport && item.transport.type) || 'tcp' })); break;
      case 'vless': nodes.push(Object.assign({ type: 'vless' }, base, { uuid: item.uuid || '', flow: item.flow || '', network: (item.transport && item.transport.type) || 'tcp', tls: tlsEnabled ? (tlsObj.reality ? 'reality' : 'tls') : 'none', sni: sni })); break;
      case 'hysteria': nodes.push(Object.assign({ type: 'hysteria' }, base, { auth: item.auth_str || '', upMbps: item.up || item.up_mbps || '', downMbps: item.down || item.down_mbps || '', sni: sni })); break;
      case 'hysteria2': nodes.push(Object.assign({ type: 'hysteria2' }, base, { password: item.password || '', upMbps: item.up || '', downMbps: item.down || '', sni: sni })); break;
      case 'tuic': nodes.push(Object.assign({ type: 'tuic' }, base, { password: item.password || '', uuid: item.uuid || '', sni: sni, congestionControl: item.congestion_control || 'bbr' })); break;
      case 'http': nodes.push(Object.assign({ type: 'http' }, base, { username: item.username || '', password: item.password || '', tls: tlsEnabled })); break;
      case 'socks': nodes.push(Object.assign({ type: 'socks5' }, base, { username: item.username || '', password: item.password || '' })); break;
    }
  }
  return nodes;
}

// ═══════════════════════════════════════════════════════════
//  parseNode - 单链接分发
// ═══════════════════════════════════════════════════════════

function parseNode(uri) {
  if (!uri || typeof uri !== 'string') return null;
  uri = uri.trim();
  if (!uri || uri[0] === '#' || uri.startsWith('//')) return null;

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

  return null;
}

// ═══════════════════════════════════════════════════════════
//  parseSubscription - 订阅内容批量解析
// ═══════════════════════════════════════════════════════════

function parseSubscription(content) {
  if (!content || typeof content !== 'string') return [];
  content = content.trim();
  if (!content) return [];

  // 0. SSD
  if (content.startsWith('ssd://')) return parseSSD(content);

  // 1. Clash YAML
  if (/"?[Pp]rox(?:y|ies)"?\s*:/.test(content)) {
    var clashNodes = parseClashYAML(content);
    if (clashNodes.length > 0) return clashNodes;
  }

  // 2. Sing-box JSON
  if (content.indexOf('"outbounds"') >= 0 && content.indexOf('"type"') >= 0) {
    try { var json = JSON.parse(content); if (json.outbounds) return parseSingboxOutbounds(json.outbounds); } catch(e) {}
  }

  // 3. Surge
  if (content.indexOf('[Proxy]') >= 0) {
    var surgeNodes = parseSurgeConf(content);
    if (surgeNodes.length > 0) return surgeNodes;
  }

  // 4. Base64 decode if needed
  var decoded = content;
  if (content.indexOf('://') < 0 && content.indexOf(' = ') < 0) {
    try {
      decoded = urlSafeBase64Decode(content);
      if (decoded.indexOf('://') < 0 && decoded.indexOf(' = ') < 0) decoded = content;
    } catch(e) {}
  }

  // 5. Surge-like (decoded base64)
  if (decoded.indexOf(' = ') >= 0 && /(vmess|ss|trojan|http|shadowsocks)\s*=/.test(decoded)) {
    return parseSurgeLike(decoded);
  }

  // 6. Line-by-line
  var newlineCount = (decoded.match(/\n/g) || []).length;
  var crCount = (decoded.match(/\r/g) || []).length;
  var delimiter = '\n';
  if (newlineCount < 1 && crCount >= 1) delimiter = '\r';

  var lines = decoded.split(delimiter);
  var nodes = [];
  for (var i = 0; i < lines.length; i++) {
    var node = parseNode(lines[i].trim());
    if (node) nodes.push(node);
  }
  return nodes;
}

// Surge-like (decoded base64 with "key = value")
function parseSurgeLike(content) {
  var nodes = [];
  var lines = content.split(/\n|\r\n?/);
  for (var i = 0; i < lines.length; i++) {
    var trimmed = lines[i].trim();
    if (!trimmed) continue;
    var eqPos = trimmed.indexOf('=');
    if (eqPos < 0) continue;
    var name = trimmed.substring(0, eqPos).trim();
    var value = trimmed.substring(eqPos + 1).trim();
    var parts = value.split(',').map(function(s) { return s.trim(); });
    if (parts.length < 3) continue;
    var type = parts[0];
    var lastColon = parts[0].lastIndexOf(':');
    var server = lastColon > 0 ? parts[0].substring(0, lastColon) : parts[1];
    var port = lastColon > 0 ? parts[0].substring(lastColon + 1) : parts[2];
    if (!server || !port || port === '0') continue;

    if (type === 'vmess') {
      var node = parseVMessQuan(name + ' = vmess,' + parts.slice(1).join(','));
      if (node) nodes.push(node);
    } else if (type === 'ss' || type === 'shadowsocks') {
      var method = '', password = '', plugin = '', pluginOpts = '';
      for (var j = 2; j < parts.length; j++) {
        var kv = parts[j].split('='); if (kv.length < 2) continue;
        var k = kv[0].trim(), v = kv[1].trim();
        if (k === 'method') method = v;
        else if (k === 'password') password = v;
        else if (k === 'obfs') { plugin = v === 'ws' ? 'v2ray-plugin' : 'obfs-local'; pluginOpts = v; }
        else if (k === 'obfs-host') pluginOpts += ';obfs-host=' + v;
      }
      nodes.push(buildNode('ss', server, port, { name: name, cipher: method, password: password, plugin: plugin, pluginOpts: pluginOpts }));
    } else if (type === 'trojan') {
      var password = '', sni = '';
      for (var j = 2; j < parts.length; j++) {
        var kv = parts[j].split('='); if (kv.length < 2) continue;
        if (kv[0].trim() === 'password') password = kv[1].trim();
        else if (kv[0].trim() === 'tls-host') sni = kv[1].trim();
      }
      nodes.push(buildNode('trojan', server, port, { name: name, password: password, sni: sni || server, udp: true }));
    }
  }
  return nodes;
}



// ═══════════════════════════════════════════════════════════
//  网络 & 构架
// ═══════════════════════════════════════════════════════════

const REGION_MAP = [
  ['香港','🇭🇰'],['台湾','🇨🇳'],['日本','🇯🇵'],['美国','🇺🇸'],['韩国','🇰🇷'],['新加坡','🇸🇬'],
  ['英国','🇬🇧'],['德国','🇩🇪'],['印度','🇮🇳'],['越南','🇻🇳'],['泰国','🇹🇭'],['菲律宾','🇵🇭'],
  ['加拿大','🇨🇦'],['澳大利亚','🇦🇺'],['澳门','🇲🇴'],['马来西亚','🇲🇾'],['俄罗斯','🇷🇺'],
  ['土耳其','🇹🇷'],['印度尼西亚','🇮🇩'],['巴西','🇧🇷'],['阿根廷','🇦🇷'],['法国','🇫🇷'],['意大利','🇮🇹'],
];
const RULE_STORE = new Map();
const BASE = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/';
const RULESETS = {
  '🎯 全球直连': ['LocalAreaNetwork.list','UnBan.list','GoogleCN.list','ChinaDomain.list','ChinaCompanyIp.list','Download.list'],
  '🛑 广告拦截': ['BanAD.list'], '🍃 应用净化': ['BanProgramAD.list'],
  '📢 谷歌FCM': ['Ruleset/GoogleFCM.list'], 'Ⓜ️ 微软Bing': ['Bing.list'],
  'Ⓜ️ 微软云盘': ['OneDrive.list'], 'Ⓜ️ 微软服务': ['Microsoft.list'],
  '🍎 苹果服务': ['Apple.list'], '📲 电报消息': ['Telegram.list'],
  '📹 油管视频': ['Ruleset/YouTube.list'], '🎥 奈飞视频': ['Ruleset/Netflix.list'],
  '📺 哔哩哔哩': ['Ruleset/Bilibili.list','Ruleset/BilibiliHMT.list'],
  '🌍 国外媒体': ['ProxyMedia.list'], '🌏 国内媒体': ['ChinaMedia.list'],
  '🎶 网易音乐': ['Ruleset/NetEaseMusic.list'],
  '💬 Ai平台': ['Ruleset/AI.list','Ruleset/OpenAi.list'],
  '🎮 游戏平台': ['Ruleset/Steam.list','Ruleset/Epic.list','Ruleset/Sony.list','Ruleset/Nintendo.list'],
};
function detectRegion(name) { for (const [kw, flag] of REGION_MAP) { if (name.includes(kw)) return { kw, flag }; } return null; }
async function fetchNodes(subUrl) {
  const resp = await fetch(subUrl, { headers: { 'User-Agent': 'ProxyPress/5.0', 'Accept': '*/*' } });
  let body = await resp.text();
  const nodes = parseSubscription(body);
  for (const n of nodes) { const r = detectRegion(n.name); n.region = r ? r.kw : null; n.flag = r ? r.flag : null; }
  return nodes;
}
async function fetchRules() {
  const rules = [], ps = [];
  for (const [group, files] of Object.entries(RULESETS)) {
    for (const f of files) {
      ps.push(fetch(BASE + f, { headers: { 'User-Agent': 'ProxyPress/5.0' } }).then(r => r.text()).then(t => {
        for (const line of t.split('\n')) {
          const s = line.trim(); if (!s || s.startsWith('#')) continue;
          const parts = s.split(','), last = parts[parts.length - 1].trim();
          if (last === 'no-resolve' || last === 'src' || last === 'dst' || !last || parts.length < 3) rules.push({ group, line: s + ',' + group });
          else rules.push({ group, line: s });
        }
      }).catch(() => {}));
    }
  }
  await Promise.all(ps);
  rules.push({ group: '🎯 全球直连', line: 'GEOIP,CN,🎯 全球直连' });
  rules.push({ group: '🐟 漏网之鱼', line: 'MATCH,🐟 漏网之鱼' });
  return rules;
}
export default {
  async fetch(request) {
    const u = new URL(request.url), p = u.pathname;
    if (p === '/health') return new Response('OK');
    if (p === '/sub') {
      const rawUrl = u.searchParams.get('url'), mode = u.searchParams.get('mode') || 'inline';
      if (!rawUrl) return new Response('Missing url', { status: 400 });
      try {
        const nodes = await fetchNodes(decodeURIComponent(rawUrl));
        if (!nodes.length) return new Response('No nodes', { status: 400 });
        globalThis._nodes = nodes;
        const rules = await fetchRules();
        const r = mode === 'provider' ? buildProvider(nodes, rules, u.origin, rawUrl) : buildInline(nodes, rules);
        return new Response(r, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=300' } });
      } catch(e) { return new Response('Error: ' + e.message, { status: 502 }); }
    }
    if (p === '/list') {
      const rawUrl = u.searchParams.get('url');
      if (!rawUrl) return new Response('Missing url', { status: 400 });
      const nodes = await fetchNodes(decodeURIComponent(rawUrl));
      const y = ['proxies:'];
      for (const n of nodes) y.push('  - {name: ' + JSON.stringify(n.name) + ', server: ' + n.server + ', port: ' + n.port + ', type: ' + n.type + ', password: ' + JSON.stringify(n.password || '') + ', cipher: ' + JSON.stringify(n.cipher || '') + ', udp: ' + !!n.udp + ', fingerprint: ' + (n.fingerprint || 'chrome') + ', sni: ' + (n.sni || n.server) + ', skip-cert-verify: ' + !!n['skip-cert-verify'] + '}');
      return respond(y.join('\n'), 300);
    }
    if (p.startsWith('/rules/')) { const h = p.split('/rules/')[1].replace('.yaml',''); return RULE_STORE.has(h) ? respond(RULE_STORE.get(h), 86400) : new Response('Not found', { status: 404 }); }
    return new Response('ProxyPress v5', { status: 404 });
  }
};
function respond(body, max) { return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=' + max } }); }
function buildInline(nodes, rules) {
  const lines = ['port: 7890','socks-port: 7891','allow-lan: true','mode: Rule','log-level: info','','proxies:'];
  for (const n of nodes) lines.push('  - {name: ' + JSON.stringify(n.name) + ', server: ' + n.server + ', port: ' + n.port + ', type: ' + n.type + ', password: ' + JSON.stringify(n.password || '') + ', cipher: ' + JSON.stringify(n.cipher || '') + ', udp: ' + !!n.udp + ', fingerprint: ' + (n.fingerprint || 'chrome') + ', sni: ' + (n.sni || n.server) + ', skip-cert-verify: ' + !!n['skip-cert-verify'] + '}');
  lines.push(...mgroups(nodes), ...mrules(rules));
  return lines.join('\n');
}
function buildProvider(nodes, rules, host, rawUrl) {
  const lines = ['port: 7890','socks-port: 7891','allow-lan: true','mode: Rule','log-level: info','',
    'proxy-providers:','  provider:','    type: http','    path: ./proxy-providers/provider.yaml',
    '    url: ' + host + '/list?url=' + encodeURIComponent(decodeURIComponent(rawUrl)),
    '    interval: 86400','    health-check:','      enable: true','      url: http://www.gstatic.com/generate_204','      interval: 300','',
    'rule-providers:'];
  const rgs = {};
  for (const r of rules) { if (!rgs[r.group]) rgs[r.group] = []; rgs[r.group].push(r.line); }
  const refs = [];
  for (const [g, ls] of Object.entries(rgs)) {
    const c = ls.join('\n'), h = simpleHash(c), n = g.replace(/[^\w\u4e00-\u9fff]/g,'_').replace(/_+/g,'_').replace(/^_|_$/g,'')||'o';
    RULE_STORE.set(h, c);
    lines.push('  ' + n + ':','    type: http','    behavior: classical','    path: ./rulesets/' + n + '.yaml','    url: ' + host + '/rules/' + h + '.yaml','    interval: 86400');
    refs.push('  - RULE-SET,' + n + ',' + g);
  }
  lines.push('', ...pgroups(nodes), '', 'rules:', ...refs);
  return lines.join('\n');
}
function mgroups(nodes) {
  const ls = ['','proxy-groups:'], rs = new Map();
  for (const n of nodes) { if (n.region && !rs.has(n.region)) rs.set(n.region, n.flag || ''); }
  ls.push('  - name: 🚀 节点选择','    type: select','    proxies:','      - ♻️ 自动选择');
  for (const [r,f] of rs) ls.push('      - ' + f + ' ' + r + '节点');
  ls.push('      - 🚀 手动切换','      - DIRECT');
  ls.push('  - name: 🚀 手动切换','    type: select','    proxies:');
  for (const n of nodes) ls.push('      - ' + n.name);
  ls.push('      - DIRECT');
  ls.push('  - name: ♻️ 自动选择','    type: url-test','    proxies:');
  for (const n of nodes) ls.push('      - ' + n.name);
  ls.push('    url: http://www.gstatic.com/generate_204','    interval: 300','    tolerance: 50');
  for (const [r,f] of rs) {
    const rn = nodes.filter(n => n.region === r);
    if (rn.length) { ls.push('  - name: ' + f + ' ' + r + '节点','    type: url-test','    proxies:'); for (const n of rn) ls.push('      - ' + n.name); ls.push('    url: http://www.gstatic.com/generate_204','    interval: 300','    tolerance: 50'); }
  }
  atargets(ls); return ls;
}
function pgroups(nodes) {
  const ls = ['proxy-groups:'], rs = new Map();
  for (const n of nodes) { if (n.region && !rs.has(n.region)) rs.set(n.region, n.flag || ''); }
  ls.push('  - name: 🚀 节点选择','    type: select','    proxies:','      - ♻️ 自动选择');
  for (const [r,f] of rs) ls.push('      - ' + f + ' ' + r + '节点');
  ls.push('      - 🚀 手动切换','      - DIRECT');
  ls.push('  - name: 🚀 手动切换','    type: select','    proxies:');
  for (const n of nodes) ls.push('      - ' + n.name);
  ls.push('      - DIRECT');
  ls.push('  - name: ♻️ 自动选择','    type: url-test','    use:','      - provider','    url: http://www.gstatic.com/generate_204','    interval: 300','    tolerance: 50');
  for (const [r,f] of rs) {
    ls.push('  - name: ' + f + ' ' + r + '节点','    type: url-test','    use:','      - provider','    filter: "' + r + '"','    url: http://www.gstatic.com/generate_204','    interval: 300','    tolerance: 50');
  }
  atargets(ls); return ls;
}
function atargets(ls) {
  const ts = ['🎯 全球直连','🛑 广告拦截','🍃 应用净化','🐟 漏网之鱼','📲 电报消息','📹 油管视频','🎥 奈飞视频','📺 哔哩哔哩','🌍 国外媒体','🌏 国内媒体','📢 谷歌FCM','Ⓜ️ 微软Bing','Ⓜ️ 微软云盘','Ⓜ️ 微软服务','🍎 苹果服务','🎶 网易音乐','💬 Ai平台','🎮 游戏平台'];
  for (const t of ts) {
    if (t === '🎯 全球直连') { ls.push('  - name: ' + t,'    type: select','    proxies:','      - DIRECT','      - 🚀 节点选择'); }
    else if (t === '🛑 广告拦截' || t === '🍃 应用净化') { ls.push('  - name: ' + t,'    type: select','    proxies:','      - REJECT','      - DIRECT'); }
    else if (t === '🐟 漏网之鱼') { ls.push('  - name: ' + t,'    type: select','    proxies:','      - 🚀 节点选择','      - DIRECT','      - ♻️ 自动选择'); }
    else { ls.push('  - name: ' + t,'    type: select','    proxies:','      - 🚀 节点选择','      - ♻️ 自动选择','      - DIRECT'); }
  }
}
function mrules(rules) { const ls = ['','rules:']; for (const r of rules) ls.push('  - ' + r.line); return ls; }
function simpleHash(s) { let h=0; for(let i=0;i<s.length;i++){ h=((h<<5)-h)+s.charCodeAt(i); h|=0; } return Math.abs(h).toString(16).padStart(8,'0').slice(0,8); }
