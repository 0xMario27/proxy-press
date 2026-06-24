#!/usr/bin/env python3
"""从 server.js 提取共享逻辑 → shared.js"""
import re

server = open('backend/server.js').read()

start = server.find('常量')
start = server.rfind('// ═', 0, start)
end = server.find('HTTP 请求处理')
end = server.rfind('// ═', 0, end)
shared = server[start:end]

# 去掉平台相关的 I/O 函数
shared = re.sub(r'(async\s+)?function fetchText\([^)]*\).*?^\}', '', shared, flags=re.MULTILINE | re.DOTALL)
shared = re.sub(r'(async\s+)?function fetchAndParseSub\([^)]*\).*?^\}', '', shared, flags=re.MULTILINE | re.DOTALL)
shared = re.sub(r'^async\s*$', '', shared, flags=re.MULTILINE)

open('backend/shared.js', 'w').write(shared)
print(f'✅ shared.js updated ({len(shared)} chars)')
