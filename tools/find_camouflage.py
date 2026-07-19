#!/usr/bin/env python3
"""
find_camouflage —— 为 Mirage 自动寻找「SNI/IP 一致」的伪装站候选 (零 API key)。

背景 (抗识别硬化 · SNI/IP 一致性):
  Mirage 的 camouflage_host (SNI) 和目的 IP 若不在同一网络 (如 SNI=speedtest.net 打到
  某小机房 VPS), 企业 NGFW 的 "SNI 归属 ASN vs 目的 IP ASN" 一致性检查会盯上它。
  本工具找一个**真实托管在你 VPS 同 ASN**的域名当 camouflage_host, 让 SNI 和 IP 名实相符。

核心手法 (无需付费 passive DNS):
  一个 IP 的 :443 证书里, SubjectAltName 就列着它服务的域名。所以扫你 ASN 的 IP 段、
  抓证书读 SAN, 直接得到"域名 ↔ 它所在的 IP(在你 ASN 内)"。

数据源 (全 keyless):
  · RIPEstat REST (data.ripe.net): IP→ASN+前缀, ASN→announced 前缀。无需 key。
  · 直连目标 :443 抓证书 (Python ssl) + openssl 读 SAN。
  · socket 解析候选域名 → 校验它是否解析回你的 ASN。

能到什么程度 (务必看清):
  ✓ ASN/前缀级一致 —— 打掉绝大多数企业 NGFW 的一致性检查 (它们做 ASN/类目级)。
  ✗ 不是精确 IP 绑定 —— 若防火墙要求"连接必须去 SNI 解析出的确切 IP", 只能用你自有域名
    指向自己 VPS。本工具会把"恰好解析到你 VPS 确切 IP/同一 /24"的候选标为 BEST。
  · 候选站不是你的, 且可能搬离你 ASN → 定期复跑。
  · 同 ASN 站通常网络很近 → auth-fail 转发 RTT 小, 顺带改善时序侧信道。

⚠️ 这会对一段 IP 的 :443 做轻量扫描 —— 默认只扫你 VPS 的覆盖前缀 (通常一个 /24), 已限速。
   别无脑 --scan-asn 扫整个 ASN 的上千 IP (慢 + 可能被上游判定端口扫描)。

用法:
  python3 find_camouflage.py <你的VPS_IP> [--scan-asn] [--limit 256] [--workers 40]
依赖: python3 stdlib + openssl CLI (几乎系统自带)。无 pip, 无 API key。
"""
import argparse
import concurrent.futures as cf
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import urllib.request

RIPE = "https://stat.ripe.net/data"
TIMEOUT = 4.0


def ripe(endpoint, resource):
    url = f"{RIPE}/{endpoint}/data.json?resource={resource}"
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.load(r)["data"]


def ip_to_asn(ip):
    """IP → (asn, holder, 覆盖前缀)。"""
    d = ripe("network-info", ip)
    asns = d.get("asns") or []
    prefix = d.get("prefix")
    asn = asns[0] if asns else None
    holder = None
    if asn:
        try:
            ov = ripe("as-overview", f"AS{asn}")
            holder = ov.get("holder")
        except Exception:
            pass
    return asn, holder, prefix


def asn_prefixes(asn):
    d = ripe("announced-prefixes", f"AS{asn}")
    return [p["prefix"] for p in d.get("prefixes", []) if ":" not in p["prefix"]]  # 仅 IPv4


def get_cert_sans(ip):
    """连 ip:443 抓默认证书 (无 SNI), 返回 SAN 里的 DNS 名 + 证书 issuer。失败返回 ([],None)。"""
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=None) as ss:
                der = ss.getpeercert(binary_form=True)
        if not der:
            return [], None
        pem = ssl.DER_cert_to_PEM_cert(der)
        out = subprocess.run(
            ["openssl", "x509", "-noout", "-ext", "subjectAltName", "-issuer"],
            input=pem, capture_output=True, text=True, timeout=6,
        ).stdout
        sans = re.findall(r"DNS:([^,\s]+)", out)
        m = re.search(r"issuer=.*?(?:CN\s*=\s*|O\s*=\s*)([^,\n/]+)", out)
        issuer = m.group(1).strip() if m else "?"
        # 去通配、去纯 IP、小写去重
        clean = []
        for s in sans:
            s = s.lower().lstrip("*.")
            if s and "." in s and not re.match(r"^\d+\.\d+\.\d+\.\d+$", s) and s not in clean:
                clean.append(s)
        return clean, issuer
    except Exception:
        return [], None


def supports_tls13(host):
    ctx = ssl._create_unverified_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.version() == "TLSv1.3"
    except Exception:
        return False


def http_probe(host):
    """取 https 首页状态 + Server 头 (可达性/合理性)。"""
    try:
        req = urllib.request.Request(f"https://{host}/", method="HEAD",
                                     headers={"User-Agent": "Mozilla/5.0"})
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return r.status, r.headers.get("Server", "")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Server", "") if e.headers else ""
    except Exception:
        return None, ""


def main():
    ap = argparse.ArgumentParser(description="为 Mirage 找同 ASN 的伪装站候选 (零 API key)")
    ap.add_argument("vps_ip", help="你的 VPS 公网 IP")
    ap.add_argument("--scan-asn", action="store_true", help="扫整个 ASN 前缀 (慢, 默认只扫 VPS 覆盖前缀)")
    ap.add_argument("--limit", type=int, default=256, help="最多扫多少个 IP (默认 256)")
    ap.add_argument("--workers", type=int, default=40, help="并发数 (默认 40)")
    args = ap.parse_args()

    print(f"[1/4] 查 {args.vps_ip} 的 ASN...", file=sys.stderr)
    asn, holder, prefix = ip_to_asn(args.vps_ip)
    if not asn:
        print("❌ 查不到 ASN", file=sys.stderr); sys.exit(1)
    print(f"      AS{asn} ({holder}) 覆盖前缀 {prefix}", file=sys.stderr)
    vps_net = ipaddress.ip_network(prefix, strict=False)
    vps_ip = ipaddress.ip_address(args.vps_ip)
    vps_24 = ipaddress.ip_network(f"{vps_ip}/24", strict=False)

    # 目标 IP 集
    nets = [vps_net]
    if args.scan_asn:
        try:
            nets = [ipaddress.ip_network(p, strict=False) for p in asn_prefixes(asn)]
            print(f"[2/4] --scan-asn: {len(nets)} 个前缀", file=sys.stderr)
        except Exception as e:
            print(f"      拉 ASN 前缀失败 ({e}), 回落只扫 VPS 前缀", file=sys.stderr)
    targets = []
    for net in nets:
        for ip in net.hosts():
            targets.append(str(ip))
            if len(targets) >= args.limit:
                break
        if len(targets) >= args.limit:
            break
    print(f"[2/4] 扫 {len(targets)} 个 IP 的 :443 证书...", file=sys.stderr)

    # 并发抓证书
    domain_ips = {}   # domain -> set(ip)
    ip_issuer = {}
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(get_cert_sans, ip): ip for ip in targets}
        for fut in cf.as_completed(futs):
            ip = futs[fut]
            sans, issuer = fut.result()
            for d in sans:
                domain_ips.setdefault(d, set()).add(ip)
                ip_issuer[(d, ip)] = issuer

    if not domain_ips:
        print("\n没扫到任何带域名证书的主机。试试 --scan-asn, 或换个更'热闹'的机房。", file=sys.stderr)
        sys.exit(0)

    print(f"[3/4] 得到 {len(domain_ips)} 个候选域名, 并行校验解析/TLS1.3/HTTP...", file=sys.stderr)

    def validate(item):
        dom, ips = item
        try:
            rip = socket.gethostbyname(dom)
        except Exception:
            rip = None
        ripa = ipaddress.ip_address(rip) if rip else None
        same_ip = ripa == vps_ip
        same_24 = ripa in vps_24 if ripa else False
        same_prefix = ripa in vps_net if ripa else False  # 解析回的 IP 仍在本前缀 = 一致性判据
        # 仅对"解析回本前缀"的候选做 TLS1.3/HTTP 深探 (无关的不浪费时间)
        tls13 = supports_tls13(dom) if same_prefix else False
        status, server = (http_probe(dom) if same_prefix else (None, ""))
        score = 0
        if same_ip: score += 100
        elif same_24: score += 60
        elif same_prefix: score += 40
        if tls13: score += 10
        if status and 200 <= status < 400: score += 5
        return (score, dom, rip, same_ip, same_24, same_prefix, tls13, status, server,
                ip_issuer.get((dom, next(iter(ips))), "?"))

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        rows = list(ex.map(validate, domain_ips.items()))
    rows.sort(reverse=True)
    print("\n[4/4] 候选伪装站 (按一致性/可用性排序):\n")
    print(f"{'域名':<38} {'解析IP':<16} {'一致性':<10} {'TLS1.3':<7} {'HTTP':<6} {'issuer'}")
    print("-" * 100)
    best = None
    for r in rows[:30]:
        score, dom, rip, same_ip, same_24, same_prefix, tls13, status, server, issuer = r
        cons = "★精确IP" if same_ip else ("同/24" if same_24 else ("同前缀" if same_prefix else "跨段"))
        if best is None and same_prefix and tls13 and status and 200 <= status < 400:
            best = dom
        print(f"{dom:<38} {str(rip):<16} {cons:<10} {'是' if tls13 else '否':<7} "
              f"{str(status):<6} {issuer[:24]}")

    print("\n" + "=" * 60)
    if best:
        print(f"✅ 推荐 camouflage_host: {best}")
        print(f'   config 改法: "camouflage_host": "{best}"')
        print("   (它解析回你 VPS 的 ASN 前缀 + 供 TLS1.3 + HTTP 可达)")
    else:
        print("⚠️ 没有'解析回本前缀 + TLS1.3 + HTTP 可达'的理想候选。")
        print("   可看上面'同/24'或'同前缀'但 TLS1.3=否的, 或 --scan-asn 扩大搜索。")
    print("\n务必记住:")
    print("  · 这是 ASN/前缀级一致 (打掉常见 NGFW 检查), 非精确 IP 绑定; 最强一致仍是自有域名指向自己 VPS。")
    print("  · 候选站非你所有、可能搬迁/下线 → 定期复跑复验。")
    print("  · ⚠️ 廉价机房的同段邻居**很可能也是代理服务器** (随机子域/.xyz/Let's Encrypt 是特征)。")
    print("    选之前手动看一眼: 浏览器打开它, 是真站(有内容 200)才用; 若也是伪装转发/空响应则换一个,")
    print("    别拿另一台代理当自己的伪装站 (它被封/异常会连累你, 且 active-probe 转发到它行为可能不自洽)。")
    print("  · 理想: 200 + 有真实内容 + 类目正常的小站; 它顺带让 auth-fail 转发 RTT 很小 (同机房) = 时序也改善。")


if __name__ == "__main__":
    main()
