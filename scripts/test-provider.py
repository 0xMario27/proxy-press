#!/usr/bin/env python3
"""测试 proxy-provider 模式输出"""
import sys, re, urllib.parse, urllib.request

if len(sys.argv) < 2:
    print("用法: test-provider.py <订阅URL>")
    sys.exit(1)

sub_url = sys.argv[1]
encoded = urllib.parse.quote(sub_url, safe='')

config_url = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini"
api_url = f"http://localhost:25600/sub?target=clash&url={encoded}&config={urllib.parse.quote(config_url, safe='')}&emoji=true"

print(f"📡 请求: {api_url[:100]}...")
try:
    with urllib.request.urlopen(api_url, timeout=120) as resp:
        data = resp.read().decode('utf-8', errors='ignore')
except Exception as e:
    print(f"❌ 请求失败: {e}")
    sys.exit(1)

print(f"📦 大小: {len(data):,} bytes")
print(f"proxy-providers: {'✅' if 'proxy-providers:' in data else '❌'}")
print(f"内联 proxies:    {'❌ 还存在' if re.search(r'^proxies:', data, re.MULTILINE) else '✅ 已移除'}")
print(f"use: [provider]: {data.count(chr(10)+'    use:')} 组")
print(f"filter:          {data.count(chr(10)+'    filter:')} 组")
print(f"rules:           {'✅' if 'rules:' in data else '❌'}")
