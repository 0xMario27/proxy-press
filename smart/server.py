"""
sub-smart: 精简统一后端
- /sub?mode=provider → proxy-providers 输出
- /sub?mode=inline   → 内联 proxies 输出
- 订阅拉取代理: /fetch?url=... → 自动修正 Content-Type
"""

import http.server
import urllib.request
import urllib.parse
import os
import sys
import re
import hashlib

# 导入转换逻辑（同目录下的本地副本）
import to_provider

SUBCONVERTER = "http://subconverter:25500"
PORT = 25600


def looks_like_base64(data: bytes) -> bool:
    text = data.decode('utf-8', errors='ignore').strip()
    if re.match(r'^[A-Za-z0-9+/=\s\r\n]+$', text) and len(text) > 50:
        return b'<!DOCTYPE' not in data and b'<html' not in data
    return False


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(p.query)
        flat = {k: v[0] for k, v in params.items()}

        # /rules/<hash>.yaml - rule-provider 文件端点
        if p.path.startswith('/rules/') and p.path.endswith('.yaml'):
            hash_key = p.path.split('/rules/')[1].replace('.yaml', '')
            rules = to_provider.RULE_CACHE.get(hash_key, [])
            if rules:
                self._respond(200, 'text/plain; charset=utf-8', '\n'.join(rules).encode())
            else:
                self._respond(404, 'text/plain', b'Rules not found')
            return

        # /health
        if p.path == '/health':
            self._ok('OK')
            return

        # /version
        if p.path == '/version':
            try:
                with urllib.request.urlopen(f"{SUBCONVERTER}/version", timeout=5) as r:
                    self._ok(r.read().decode())
            except Exception as e:
                self._err(str(e))
            return

        # /fetch - 订阅代理（修复 Content-Type）
        if p.path == '/fetch':
            url = flat.get('url', '')
            if not url:
                self._err("缺少 url 参数")
                return
            try:
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'sub-smart/1.0', 'Accept': '*/*'
                })
                with urllib.request.urlopen(req, timeout=30) as r:
                    raw = r.read()
                ct = 'text/plain; charset=utf-8'
                self._respond(200, ct, raw)
            except Exception as e:
                self._err(str(e))
            return

        # /sub - 订阅转换
        if p.path == '/sub':
            mode = flat.pop('mode', 'provider')

            query = urllib.parse.urlencode(flat)
            target = f"{SUBCONVERTER}/sub?{query}"

            try:
                req = urllib.request.Request(target, headers={'User-Agent': 'sub-smart/1.0'})
                with urllib.request.urlopen(req, timeout=120) as r:
                    raw = r.read().decode('utf-8', errors='ignore')
            except Exception as e:
                self._err(f"subconverter 错误: {e}")
                return

            # 统一换行符
            raw = raw.replace('\r\n', '\n').replace('\r', '\n')

            sub_url = urllib.parse.unquote(flat.get('url', ''))
            host_ip = os.environ.get('HOST_IP', 'localhost')
            
            if mode == 'provider':
                # proxy-provider + rule-provider
                result = to_provider.convert(raw, sub_url, f"{host_ip}:25500", f"{host_ip}:25600")
            else:
                # 仅 rule-provider（proxy 保持内联）
                result = to_provider.convert_rules_to_providers(raw, f"{host_ip}:25600")

            self._ok(result)
            return

        self._respond(404, 'text/plain', b'Not Found')

    def _ok(self, body: str):
        self._respond(200, 'text/plain; charset=utf-8', body.encode())

    def _err(self, msg: str):
        self._respond(500, 'text/plain', msg.encode())

    def _respond(self, code, ct, body):
        self.send_response(code)
        self.send_header('Content-Type', ct)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        try:
            print(f"[smart] {fmt % args}", flush=True)
        except:
            print(f"[smart] {fmt}", flush=True)


if __name__ == '__main__':
    httpd = http.server.HTTPServer(('0.0.0.0', PORT), Handler)
    print(f"[smart] :{PORT} | GET /sub?mode=provider|inline", flush=True)
    httpd.serve_forever()
