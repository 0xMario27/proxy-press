#!/usr/bin/env python3
"""GFWList parser: 拉取 → 解析 → 生成 ACL / Clash 规则文件"""

import base64, re, os, sys
from glob import glob
from urllib.request import urlopen

GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

# ── 预编译正则 ──
_RE_IPV4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_RE_IPV6 = re.compile(r'^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$|^::$|^::1$')
_RE_IPV4IN6 = re.compile(r'^::ffff:(\d{1,3}\.){3}\d{1,3}$')
_RE_DOMAIN = re.compile(r'(?:https?://)?(?:www\.)?([^/:]+)')

# ── 工具 ──

def _is_ipv4(s: str) -> bool:
    return bool(_RE_IPV4.match(s) and all(0 <= int(p) <= 255 for p in s.split('.')))

def _is_ipv6(s: str) -> bool:
    return bool(_RE_IPV6.match(s) or _RE_IPV4IN6.match(s))

def _is_ip(s: str) -> bool:
    s = s.rstrip('^')
    return ('/' not in s) and ('.' in s and _is_ipv4(s) if ':' not in s else _is_ipv6(s))

def _is_cidr(s: str) -> bool:
    if '/' not in s:
        return False
    ip, suffix = s.split('/', 1)
    if not suffix.isdigit():
        return False
    n = int(suffix)
    if ':' not in ip:
        return _is_ipv4(ip) and 0 <= n <= 32
    return _is_ipv6(ip) and 0 <= n <= 128

def _normalize_ip(ip: str) -> str | None:
    ip = ip.strip().rstrip('^')
    return ip if _is_ip(ip) or _is_cidr(ip) else None

def _to_cidr(ip: str) -> str | None:
    if _is_cidr(ip):
        return ip
    if _is_ip(ip):
        return ip + ('/128' if ':' in ip else '/32')
    return None

def _extract_domain(url: str) -> str | None:
    m = _RE_DOMAIN.search(url.strip().rstrip('^').rstrip('/'))
    return m.group(1) if m and not _is_ip(m.group(1)) and not _is_cidr(m.group(1)) else None


# ── 拉取 & 解析 ──

def fetch(url: str = GFWLIST_URL) -> str:
    try:
        with urlopen(url) as r:
            return r.read().decode('utf-8')
    except Exception as e:
        sys.exit(f"Error fetching GFWList: {e}")


def parse(content: str) -> tuple[list, list, list, list]:
    """返回 (domain_black, domain_white, ip_black, ip_white)"""
    d_blk, d_wht, i_blk, i_wht = [], [], [], []

    try:
        text = base64.b64decode(content).decode('utf-8')
    except Exception:
        text = content

    # 硬编码例外
    skip = {
        '||addons.mozilla.org/*-*/firefox/addon/ublock-origin/*',
        '||addons.mozilla.org/firefox/downloads/file/*/ublock_origin-*.xpi',
    }

    for line in text.split('\n'):
        line = line.strip()
        if not line or line[0] in '![' or line in skip:
            continue

        # @@||rule  → whitelist
        if line.startswith('@@||'):
            rule = line[4:].rstrip('^')
            ip = _normalize_ip(rule)
            (i_wht if ip else d_wht).append(ip or rule)
        # ||rule  → blacklist
        elif line.startswith('||'):
            rule = line[2:].rstrip('^')
            ip = _normalize_ip(rule)
            (i_blk if ip else d_blk).append(ip or rule)
        # @@|url → whitelist domain
        elif line.startswith('@@|') and len(line) > 3:
            d = _extract_domain(line[3:])
            if d: d_wht.append(d)
        # |url → blacklist domain
        elif line.startswith('|') and len(line) > 1:
            d = _extract_domain(line[1:])
            if d: d_blk.append(d)

    return d_blk, d_wht, i_blk, i_wht


# ── 格式化 ──

def _fmt_domain_suffix(domains: list) -> list[str]:
    return [f"- DOMAIN-SUFFIX,{d}" for d in sorted(set(filter(None, domains)))]

def _fmt_acl_domains(domains: list) -> list[str]:
    return [f"(^|\\\\.){d}$" for d in sorted(set(filter(None, domains)))]

def _fmt_ip_cidr_clash(ips: list) -> list[str]:
    out = []
    for ip in sorted(set(ips)):
        n = _to_cidr(ip)
        if n:
            out.append(f"IP-CIDR6,{n},no-resolve" if ':' in n else f"IP-CIDR,{n},no-resolve")
    return out

def _fmt_ip_acl(ips: list) -> list[str]:
    return sorted(set(filter(None, ips)))


# ── 文件输出 ──

def _write(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def _write_domain_ip_split(base: str, domains: list[str], ips: list[str], fmt: str):
    """生成 _domain 和 _ip 分离文件 (fmt: 'yaml' or 'list')"""
    if domains:
        if fmt == 'yaml':
            _write(f"{base}_domain.yaml", "payload:\n" + '\n'.join(f"  - {d}" for d in domains) + '\n')
        else:
            _write(f"{base}_domain.list", '\n'.join(domains) + '\n')
    if ips:
        if fmt == 'yaml':
            _write(f"{base}_ip.yaml", "payload:\n" + '\n'.join(f"  - {i}" for i in ips) + '\n')
        else:
            _write(f"{base}_ip.list", '\n'.join(ips) + '\n')


# ── split 已有文件 ──

def _parse_yaml_line(line: str) -> tuple[str | None, str | None]:
    s = line.strip()
    if not s:
        return None, None
    rule = s[2:] if s.startswith('- ') else (s[4:] if s.startswith('  - ') else None)
    if rule and ',' in rule:
        return rule.split(',', 1)
    return (rule, '') if rule else (None, None)

def _parse_list_line(line: str) -> tuple[str | None, str | None]:
    s = line.strip()
    if not s or s.startswith('#'):
        return None, None
    return s.split(',', 1) if ',' in s else (s, '')

def _is_domain_type(t: str) -> bool:
    return t in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX')

def _is_ip_type(t: str) -> bool:
    return t in ('IP-CIDR', 'IP-CIDR6', 'IP-SUFFIX', 'IP-ASN')

def _read_existing(path: str) -> tuple[list, list]:
    """读 UnBan 等已有文件 → (domains, ips)"""
    domains, ips = [], []
    if not os.path.exists(path):
        return domains, ips
    with open(path, encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if s.startswith('- DOMAIN-SUFFIX,') or s.startswith('DOMAIN-SUFFIX,'):
                domains.append(s.split(',', 1)[1])
            elif s.startswith('- IP-CIDR') or s.startswith('  - IP-CIDR') or s.startswith('IP-CIDR'):
                parts = s.replace('  - ', '').split(',')
                if len(parts) >= 2:
                    ips.append(parts[1])
    return domains, ips


def split_existing_files():
    print("Splitting existing rule files...")
    for pattern in ['Clash/Providers/*.yaml', 'Clash/Providers/Ruleset/*.yaml']:
        for fp in glob(pattern):
            if '_domain' in fp or '_ip' in fp:
                continue
            _split_yaml(fp)
    for fp in glob('Clash/Ruleset/*.list'):
        if '_domain' in fp or '_ip' in fp:
            continue
        _split_list(fp)


def _split_yaml(fp: str):
    domains, ips = [], []
    try:
        with open(fp, encoding='utf-8') as f:
            for line in f:
                t, v = _parse_yaml_line(line)
                if not t: continue
                (domains if _is_domain_type(t) else ips).append((t, v.strip()))
    except Exception as e:
        print(f"Warning: {fp}: {e}"); return
    base = os.path.splitext(fp)[0]
    if domains:
        _write(f"{base}_domain.yaml", "payload:\n" + '\n'.join(f"  - {t},{d}" for t, d in sorted(set(domains))) + '\n')
    if ips:
        _write(f"{base}_ip.yaml", "payload:\n" + '\n'.join(f"  - {i.split(',')[0].strip()}" for _, i in sorted(set(ips))) + '\n')


def _split_list(fp: str):
    domains, ips = [], []
    try:
        with open(fp, encoding='utf-8') as f:
            for line in f:
                t, v = _parse_list_line(line)
                if not t: continue
                (domains if _is_domain_type(t) else ips).append((t, v.strip()))
    except Exception as e:
        print(f"Warning: {fp}: {e}"); return
    base = os.path.splitext(fp)[0]
    if domains:
        _write(f"{base}_domain.list", '\n'.join(f"{t},{d}" for t, d in sorted(set(domains))) + '\n')
    if ips:
        _write(f"{base}_ip.list", '\n'.join(i.split(',')[0].strip() for _, i in sorted(set(ips))) + '\n')


# ── 主流程 ──

def main():
    print("Fetching GFWList...")
    content = fetch()

    print("Parsing...")
    d_blk, d_wht, i_blk, i_wht = parse(content)
    print(f"Domain black: {len(d_blk)} | white: {len(d_wht)} | IP black: {len(i_blk)} | IP white: {len(i_wht)}")

    # 合并已有 UnBan
    for fp in ('Clash/Providers/UnBan.yaml', 'Clash/Ruleset/UnBan.list'):
        ed, ei = _read_existing(fp)
        for d in ed:
            if d and d not in d_wht: d_wht.append(d)
        for ip in ei:
            if ip and ip not in i_wht: i_wht.append(ip)
    if ed or ei:
        print(f"Merged existing UnBan: {len(ed)} domains, {len(ei)} IPs")

    # 生成文件
    _write('Acl/fullgfwlist.acl',
        f"# GFWList Blacklist\n# Generated from GFWList\n[proxy_list]\n# GFWList\n" +
        '\n'.join(_fmt_acl_domains(d_blk) + _fmt_ip_acl(i_blk)) + '\n')
    print("Generated: Acl/fullgfwlist.acl")

    _write('Clash/Providers/ProxyGFWlist.yaml',
        "payload:\n" + '\n'.join(_fmt_domain_suffix(d_blk) + _fmt_ip_cidr_clash(i_blk)) + '\n')
    print("Generated: Clash/Providers/ProxyGFWlist.yaml")

    _write('Clash/Ruleset/ProxyGFWlist.list',
        f"# GFWList Blacklist\n# {len(set(d_blk)) + len(set(i_blk))} entries\n" +
        '\n'.join(f"DOMAIN-SUFFIX,{d}" for d in sorted(set(filter(None, d_blk)))) + '\n' +
        '\n'.join(_fmt_ip_cidr_clash(i_blk)) + '\n')
    print("Generated: Clash/Ruleset/ProxyGFWlist.list")

    _write('Clash/Providers/UnBan.yaml',
        "payload:\n" + '\n'.join(_fmt_domain_suffix(d_wht) + _fmt_ip_cidr_clash(i_wht)) + '\n')
    print("Generated: Clash/Providers/UnBan.yaml")

    _write('Clash/Ruleset/UnBan.list',
        f"# GFWList Whitelist\n# {len(set(d_wht)) + len(set(i_wht))} entries\n" +
        '\n'.join(f"DOMAIN-SUFFIX,{d}" for d in sorted(set(filter(None, d_wht)))) + '\n' +
        '\n'.join(_fmt_ip_cidr_clash(i_wht)) + '\n')
    print("Generated: Clash/Ruleset/UnBan.list")

    split_existing_files()


if __name__ == "__main__":
    main()
