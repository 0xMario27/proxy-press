#!/usr/bin/env python3
"""同步 sub-converter-parser.js → worker/worker.js"""
import re

p = open('sub-converter-parser.js').read()
p = p.replace("'use strict';\n\n", "")
p = re.sub(r'\nmodule\.exports\s*=\s*\{[^}]+\};', '', p, flags=re.DOTALL)
p = p.replace("return Buffer.from(str, 'base64').toString('utf-8');", "return atob(str);")
p = p.replace("Buffer.from(str.replace(/\\s/g, ''), 'base64').toString('utf-8')", "atob(str.replace(/\\s/g, ''))")

w = open('worker/worker.js').read()
idx = w.find('const REGION_MAP')
net = w[idx:] if idx > 0 else ''

worker = "/**\n * ProxyPress Worker v5\n */\n\n" + p + "\n\n" + net
open('worker/worker.js', 'w').write(worker)
open('worker/parser.js', 'w').write(p)
print(f'✅ Synced ({len(worker)} chars)')
