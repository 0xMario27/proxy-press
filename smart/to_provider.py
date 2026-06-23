#!/usr/bin/env python3
"""subconverter 后处理器: 内联 proxies/rules → proxy-providers + rule-providers"""

import sys, re, hashlib
from urllib.parse import quote

RULE_CACHE = {}  # {hash: [rule_lines]}


# ═══════════════════════════════════════════════════════════
#  工具函数
# ═══════════════════════════════════════════════════════════

def _parse_node_names(proxies_block: str) -> set[str]:
    """从 {name: ...} 中提取节点名"""
    names = set()
    for m in re.finditer(r'name:\s*"([^"]+)"', proxies_block):
        names.add(m.group(1))
    for m in re.finditer(r'name:\s*([^,\n}]+?)(?:\s*[,}])', proxies_block):
        n = m.group(1).strip()
        if n and '"' not in n and n not in names:
            names.add(n)
    return names


def _parse_group_names(data: str) -> set[str]:
    return {m.group(1).strip() for m in re.finditer(r'^\s*- name:\s*(.+)', data, re.MULTILINE)}


_FILTER_KW = {
    '香港': '香港', '台湾': '台湾', '日本': '日本', '美国': '美国',
    '韩国': '韩国', '新加坡': '新加坡', '狮城': '新加坡',
    '英国': '英国', '德国': '德国', '印度': '印度', '越南': '越南',
    '泰国': '泰国', '菲律宾': '菲律宾', '加拿大': '加拿大',
    '澳大利亚': '澳洲', '澳门': '澳门', '埃及': '埃及',
    '缅甸': '缅甸', '蒙古': '蒙古', '老挝': '老挝', '文莱': '文莱',
    '巴基斯坦': '巴基斯坦', '马来西亚': '马来西亚', '柬埔寨': '柬埔寨',
    '意大利': '意大利', '法国': '法国', '巴西': '巴西', '阿根廷': '阿根廷',
    '俄罗斯': '俄罗斯', '土耳其': '土耳其',
}
_SKIP_FILTER = {'自动选择', '手动切换', '漏网之鱼', '节点选择'}
_SPECIALS = {'DIRECT', 'REJECT', 'REJECT-TLS', 'REJECT-DROP'}


def _get_filter(group_name: str) -> str:
    for k in _SKIP_FILTER:
        if k in group_name:
            return ''
    for cn, en in _FILTER_KW.items():
        if cn in group_name:
            return en
    return ''


def _should_convert(proxy_entries: list[str], node_names: set[str],
                    group_names: set[str]) -> bool:
    if not proxy_entries:
        return False
    nc = sum(1 for p in proxy_entries if p in node_names)
    gc = sum(1 for p in proxy_entries if p in group_names)
    sc = sum(1 for p in proxy_entries if p in _SPECIALS)
    if gc > nc and gc > 0:
        return False
    if sc == len(proxy_entries):
        return False
    return nc > 0


# ═══════════════════════════════════════════════════════════
#  主转换
# ═══════════════════════════════════════════════════════════

def convert(data: str, sub_url: str = "",
            subconverter_host: str = "localhost:25500",
            rule_host: str = "localhost:25600") -> str:
    """一步完成 proxy-provider + rule-provider 转换"""

    # ── 提取元信息 ──
    pm = re.search(r'\nproxies:\n(.*?)\nproxy-groups:', data, re.DOTALL)
    node_names = _parse_node_names(pm.group(1)) if pm else set()
    group_names = _parse_group_names(data)

    # ── 1. 替换顶层 proxies → proxy-providers ──
    list_url = (f"http://{subconverter_host}/sub?target=clash&list=true&url={quote(sub_url, safe='')}"
                if sub_url else f"http://{subconverter_host}/sub?target=clash&list=true&url=YOUR_URL")

    provider_block = (
        "proxy-providers:\n"
        "  provider:\n"
        "    type: http\n"
        "    path: ./proxy-providers/provider.yaml\n"
        f"    url: {list_url}\n"
        "    interval: 86400\n"
        "    health-check:\n"
        "      enable: true\n"
        "      url: http://www.gstatic.com/generate_204\n"
        "      interval: 300\n\n"
    )

    pstart = data.find('\nproxies:\n')
    gpos = data.find('\nproxy-groups:', pstart) if pstart > 0 else -1
    if pstart > 0 and gpos > pstart:
        data = data[:pstart + 1] + provider_block + data[gpos:]
    else:
        rpos = data.find('\nrules:') if pstart > 0 else -1
        if pstart > 0 and rpos > pstart:
            data = data[:pstart + 1] + provider_block + data[rpos:]

    # ── 2. proxy-groups: proxies → use/filter ──
    lines = data.split('\n')
    out, buf_group_lines, buf_proxies, buf_name = [], [], [], None
    in_section = False

    for line in lines:
        s = line.strip()

        # section boundary
        if s == 'proxy-groups:':
            in_section = True
            out.append(line)
            continue
        if in_section and (s.startswith('rules:') or s.startswith('rule-providers:')):
            if buf_name is not None and buf_proxies:
                _emit(out, buf_group_lines, buf_name, buf_proxies, node_names, group_names)
            elif buf_group_lines:
                out.extend(buf_group_lines)
            buf_name, buf_proxies, buf_group_lines = None, [], []
            in_section = False
            out.append(line)
            continue

        if not in_section:
            out.append(line)
            continue

        # new group
        if s.startswith('- name:'):
            if buf_name is not None and buf_proxies:
                _emit(out, buf_group_lines, buf_name, buf_proxies, node_names, group_names)
            elif buf_group_lines:
                out.extend(buf_group_lines)
            buf_name = s.split(':', 1)[1].strip()
            buf_proxies, buf_group_lines = [], [line]
            continue

        if buf_name is not None:
            buf_group_lines.append(line)
            if s.startswith('- ') and not s.startswith('- name:'):
                buf_proxies.append(s[2:].strip())
        else:
            out.append(line)

    # trailing group
    if buf_name is not None and buf_proxies:
        _emit(out, buf_group_lines, buf_name, buf_proxies, node_names, group_names)
    elif buf_group_lines:
        out.extend(buf_group_lines)

    data = '\n'.join(out)

    # ── 3. rules → rule-providers ──
    return _rules_to_providers(data, rule_host)


def _emit(out: list, group_lines: list, name: str, proxies: list,
          node_names: set, group_names: set):
    if not _should_convert(proxies, node_names, group_names):
        out.extend(group_lines)
        return
    kw = _get_filter(name)
    for line in group_lines:
        s = line.strip()
        if s.startswith('proxies:'):
            out.append('    use:')
            out.append('      - provider')
            if kw:
                out.append(f'    filter: "{kw}"')
        elif not (s.startswith('- ') or s == ''):
            out.append(line)
        # skip old proxy entries


# ═══════════════════════════════════════════════════════════
#  rules → rule-providers
# ═══════════════════════════════════════════════════════════

def _rules_to_providers(data: str, host: str) -> str:
    global RULE_CACHE
    idx = data.find('\nrules:\n')
    if idx < 0:
        return data

    before = data[:idx + 1]
    tail = data[idx + 1:]

    # 收集所有 rule 行
    rule_lines = []
    after = []
    in_rules = in_entries = False
    for line in tail.split('\n'):
        s = line.strip()
        if s == 'rules:' and not in_rules:
            in_rules = True; continue
        if in_rules:
            if s.startswith('- ') and not s.startswith('- name:'):
                rule_lines.append(line); in_entries = True
            elif in_entries and s and s.startswith(' '):
                rule_lines.append(line)
            else:
                if in_entries: in_entries = False
                after.append(line)
        else:
            after.append(line)

    if not rule_lines:
        return data

    # 按 target 分组（保持顺序）
    groups = []  # [(target, [lines])]
    cur_target, cur_block = None, []

    for line in rule_lines:
        s = line.strip()
        if s.startswith('- '):
            if cur_target and cur_block:
                groups.append((cur_target, cur_block))
            parts = s.split(',')
            if len(parts) >= 2:
                t = parts[-1].strip()
                if t == 'no-resolve' and len(parts) >= 3:
                    t = parts[-2].strip()
                cur_target = t
            else:
                cur_target = '__other__'
            cur_block = [line]
        elif s:
            cur_block.append(line)

    if cur_target and cur_block:
        groups.append((cur_target, cur_block))

    # 合并同 target 的连续块
    merged = []
    for t, block in groups:
        if merged and merged[-1][0] == t:
            merged[-1][1].extend(block)
        else:
            merged.append((t, block))

    # 生成 provider 条目
    providers, refs, seen = [], [], set()
    for target, block in merged:
        safe = re.sub(r'[^\w]', '_', target).strip('_') or 'other'
        name = safe
        if name in seen:
            n = 2
            while f'{safe}_{n}' in seen:
                n += 1
            name = f'{safe}_{n}'
        seen.add(name)

        content = '\n'.join(block)
        h = hashlib.md5(content.encode()).hexdigest()[:8]
        RULE_CACHE[h] = block

        providers.append(
            f"  {name}:\n"
            f"    type: http\n"
            f"    behavior: classical\n"
            f"    path: ./rulesets/{name}.yaml\n"
            f"    url: http://{host}/rules/{h}.yaml\n"
            f"    interval: 86400"
        )
        refs.append(f"  - RULE-SET,{name},{target}")

    return (before + '\nrule-providers:\n' + '\n'.join(providers) + '\n'
            + 'rules:\n' + '\n'.join(refs) + '\n'
            + '\n'.join(after))


def convert_rules_to_providers(data: str, host: str = "localhost:25600") -> str:
    """仅做 rule-provider 转换（保留 inline proxies）"""
    return _rules_to_providers(data, host)


# ═══════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════

def main():
    data = sys.stdin.read()
    if not data.strip():
        print("Error: empty input", file=sys.stderr)
        sys.exit(1)
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    host, sub_url = "localhost:25500", ""
    if arg.startswith('http'):
        sub_url = arg
    elif ':' in arg:
        host = arg
    print(convert(data, sub_url, host), end='')


if __name__ == '__main__':
    main()
