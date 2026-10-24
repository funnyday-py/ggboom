#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线
============================
流程:
  1. 获取 VPN Gate 原始节点 (官方 api/iphone CSV, 失败时回退 GitHub 预解析镜像)
  2. 只保留「带 TCP 入口」的中继 = SSTP 可用节点
     (OpenVPN 配置里 proto tcp + remote <ip> <port>; UDP-only 中继无法走 SSTP/xray 链, 直接丢弃)
  3. 按 host+port+protocol 去重
  4. 并发调用已部署的 Cloudflare Worker:  GET {WORKER}/check?proxyip=host:port
     (单节点 HTTP 成功 != 节点可用; 以 Worker 返回 JSON 的 success 字段为准)
  5. 保留 success=true 的节点, 按国家分组, 生成 public/data.json + public/index.html
  6. 网页端 (GitHub Pages) 读取 data.json 展示

退出码:
  0 = 正常完成 (允许部分节点检测失败)
  1 = 硬性失败 (数据源全挂 / 解析不出 SSTP 节点 / Worker 完全不可达 / 程序异常)
     这些情况绝不允许"假成功"
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

# 保证日志在任何控制台编码下都能输出 (Windows GBK 控制台不会崩)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置 (均可用环境变量覆盖, 便于本地测试)
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
# 官方接口失败时的回退数据源: 预解析 JSON 镜像 (字段与官方 CSV 同源)
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
# 已部署的 Cloudflare Worker 检测接口 (GET /check?proxyip=host:port, 实测确认)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://green-rice-2c18.zxm378t0.workers.dev/check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))   # 与 Worker 网页端一致的并发模型
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))          # 单请求客户端超时 (秒)
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))         # 0=不限; 本地测试可设小值
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))              # 拉取数据源超时
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

# 出口数据中心的关键词启发 (判断"是否住宅 IP"用, 页面标注为估算)
DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
# 常见住宅宽带运营商关键词
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

# ISO 国家码 -> 中文名 (edgetunnel 清单展示用; 未收录则回退英文原名)
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# ---------------------------------------------------------------------------
# 日志 (用户要求的分区格式)
# ---------------------------------------------------------------------------
_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    """硬性失败: 明确报错并退出非 0, 绝不允许假成功。"""
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 第 1 步: 获取 VPN Gate 原始节点
# ---------------------------------------------------------------------------
def fetch_vpngate():
    """返回 (rows, source)。rows: [{host, ip, country_long, country_short, config_b64}]
    官方 API 失败时回退镜像 JSON; 两个都失败 -> 直接 die (exit 1)。"""
    # --- 主源: 官方 CSV ---
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        resp = requests.get(
            VPNGATE_API,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"},
        )
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    # --- 回退源: GitHub 预解析镜像 ---
    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败 (不生成空结果, 本次运行判定失败)")


def parse_csv(text):
    """解析官方 CSV。表头行含 'HostName'; 按列名映射, 列名缺失时用固定位置回退。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    # 列名映射 (不假设固定位置, 列名变化时自动适配; 全缺失时回退到已知位置)
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {"hostname": idx.get("hostname", 0),
           "ip": idx.get("ip", 1),
           "countrylong": idx.get("countrylong", 5),
           "countryshort": idx.get("countryshort", 6),
           "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1)}

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7:
            continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows


def parse_mirror_json(data):
    """解析 GitHub 镜像 JSON: [ { "servers": [ {hostname, ip, countrylong, countryshort, openvpn_configdata_base64} ] } ]"""
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows


# ---------------------------------------------------------------------------
# 第 2 步: 筛选 SSTP 节点 (只保留带 TCP 入口的中继)
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


def to_sstp_nodes(rows):
    """把原始行转成 SSTP 节点: 解码 OpenVPN 配置, 仅保留 proto tcp + remote 端口。
    host 统一为 <short>.opengw.net 形式; 返回去重前的节点列表。"""
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            continue  # 无 TCP 入口 -> 不是 SSTP 可用节点, 丢弃
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host,
            "port": port,
            "ip": r["ip"],
            "country": r["country_long"],
            "country_code": r["country_short"],
        })
    return nodes


def dedupe(nodes):
    """按 host+port+protocol 去重。"""
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


# ---------------------------------------------------------------------------
# 第 3 步: 并发调用 Cloudflare Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    """住宅/机房分类, 按可信度排序:
    1) Worker 返回的真实 is_datacenter 标志 (IP 情报库);
    2) 出口 ASN 组织名关键词;
    3) host 前缀启发式 (最后兜底, 属估算)。"""
    # 1) 真实数据中心标志 (SSTP 版 Worker 顶层 exit 直接给出)
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    # 2) 出口组织名关键词
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    # 3) host 前缀启发式 (估算)
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"      # VPN Gate 官方公共中继 (机房/托管)
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"     # 数字编号 = 注册的家用宽带中继 (家宽, 估算)
    return "unknown"


def check_one(node, session):
    """调用 Worker 检测单节点。返回节点+检测结果的合并 dict。
    单节点失败 (网络错误/非 200/坏 JSON) 不会抛出, 统一记 success=False。"""
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        # SSTP 版 Worker: 顶层直接返回 exit, 含真实 is_datacenter 标志 + 嵌套 asn 对象
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out


def check_all(nodes, session):
    """32 并发 (与网页端一致)。单节点失败不影响整体; 但区分'节点不可用'与'Worker 异常'。"""
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


# ---------------------------------------------------------------------------
# 第 4 步: 生成网页数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }

    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data


CHAIN_URL = os.environ.get("CHAIN_URL", "https://funnyday-py.github.io/ggboom/chains.txt")


def build_chains_text(data):
    """生成 edgetunnel 链式代理清单: 按国家分组, 每国编号固定, 住宅优先, 延迟升序。
    每行 = 「名字 + $sstp://vpn:vpn@host:port」, 名字不变, 指令每 30 分钟自动换。"""
    countries = data["countries"]
    lines = [
        "# VPN Gate SSTP 节点 -> edgetunnel 链式代理清单",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {CHAIN_URL}",
        "#",
        "# 用法: 在 edgetunnel 节点备注里直接粘贴下面任意一行 (名字与指令连写)",
        "#   例: 日本-住宅-01$sstp://vpn:vpn@vpnxxx.opengw.net:443",
        "# 名字保持不变, 只有 $sstp:// 后面的地址每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 端口必须保留",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            lines.append(f"{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            lines.append(f"{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel 入口地址池: 客户端直连 Cloudflare 的优选 IP:端口 (循环分配给每个国家节点当入口)
# 可通过环境变量 EDGE_HOSTS 覆盖 (逗号分隔)
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "ping.pe:443,www.postman.com:443,www.ox.ac.uk:443,www.speedtest.net:443,"
        "linear.app:443,shabak.gov.il:443,newsroom.avalara.com:443",
    ).split(",")
    if h.strip()
]

HOSTS_URL = os.environ.get("HOSTS_URL", "https://funnyday-py.github.io/ggboom/hosts.txt")

# ---------------------------------------------------------------------------
# 自动优选入口源
#   实测结论 (2026-10-23, 本机 -> CF 边缘真实出站对照):
#     LancelotRar/best-cf-ips collected  6/6 可用, 中位 8.43 Mbps  <- 首选
#     LancelotRar/best-cf-domains lite   5/6 可用, 中位 4.21 Mbps  <- 次选(三网分线)
#     ludas114343/cf-speedtest-sub        4/6 可用, 中位 1.60 Mbps  <- 兜底
#   多源按顺序尝试, 每个源先按"国家分散"挑选, 某个源全挂时自动降级到下一个。
#   每次跑 workflow 拉一次, IP 失效会被下一批替换, 不用手工维护。
# ---------------------------------------------------------------------------
# 优选 IP 源 (逗号分隔, 按优先级; 格式 host:port#备注)
CF_IP_SOURCE = os.environ.get(
    "CF_IP_SOURCE",
    "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-collected.txt,"
    "https://raw.githubusercontent.com/ludas114343/cf-speedtest-sub/main/addressesapi.txt",
)
# 优选域名源 (逗号分隔, 按优先级; 格式 host:port#备注)
#   注意: 源里的"优选域名"是发布者在自己网络下测的, 本机实测普遍只有 0.2~0.5 Mbps,
#   只有 www.speedtest.net 例外(9.57 Mbps / 极差 0.70, 断层第一)。
#   所以外部域名源只作补充, 主力是下面 VERIFIED_DOMAINS。
CF_DOMAIN_SOURCE = os.environ.get(
    "CF_DOMAIN_SOURCE",
    "https://raw.githubusercontent.com/LancelotRar/best-cf-domains/main/best-cf-domain-lite.txt",
)
# 本机实测验证过的入口域名 (2026-10-23, 串行独占带宽, 3 轮端到端真实出站)
#   格式: (host:port, 中位 Mbps)  —— 按实测速度从高到低排
#   关键结论: www.speedtest.net 以 10.12 Mbps 断层第一, 极差 2.54;
#   其余所有候选(含外部源给的域名)都在 0.67 Mbps 以下。
#   外部"优选"是发布者在自己网络下测的, 本机直接用效果有限, 只能当冗余备份。
VERIFIED_DOMAINS = [
    ("www.speedtest.net:443", 10.12),  # 主力入口
    ("www.postman.com:443", 4.48),     # 冗余
    ("www.ox.ac.uk:443", 0.31),        # 冗余
]
# 本机实测验证过的优选 IP (2026-10-23, CloudflareSpeedTest v2.3.5 本机跑 + 端到端二次验证)
#   产线: 8 个源合并 798 个候选 -> CFST 测延迟/丢包 -> 取下载速度前 18 -> 端到端实测 ->
#         3 轮稳定性复测 -> 只留"全轮成功且中位 >= 2 Mbps"者。
#   格式: (host:port, 中位 Mbps)  —— 按实测速度从高到低排
#   重要: CFST 的下载速度排名对本场景没有预测力 (与端到端速度相关系数仅 r=0.424)。
#         CFST 榜首 172.67.72.176 (25.64 MB/s) 端到端只有 0.41 Mbps; 而 CFST 只排第 18 的
#         104.18.62.183 (0.02 MB/s) 端到端 8.28 Mbps。原因是 CFST 打的是 CF 自家测速站,
#         而真实路径是 本机 -> CF 边缘 -> Worker -> 第三方站, SEA colo 在这条路径上会崩。
#         所以 CFST 的价值是"扩大候选池", 不是"提供排名"。
VERIFIED_IPS = [
    ("104.18.58.130:443", 9.76),       # LAX, 极差 1.63
    ("104.18.54.222:443", 9.66),       # LAX, 极差 0.47 —— 最稳
    ("162.159.237.185:443", 9.38),     # SJC, 极差 3.39
    ("104.18.62.183:443", 8.75),       # LAX, 极差 1.48
    ("162.159.237.219:443", 8.02),     # SJC, 极差 0.71
    ("172.64.79.226:443", 7.88),       # SJC, 极差 2.63
]
CF_IP_LIMIT = max(0, int(os.environ.get("CF_IP_LIMIT", "6") or 6))
CF_DOMAIN_LIMIT = max(0, int(os.environ.get("CF_DOMAIN_LIMIT", "2") or 2))

# 实测可用的 ProxyIP 中转 (2026-10-24, 经节点访问 www.cloudflare.com/cdn-cgi/trace 8/8 全 200)。
# 背景: Worker 的 connect() 被平台禁止回连 CF 自家 IP (防回环), 访问 CF 前置站
# (dash.cloudflare.com 等) 必须经非 CF 中转; 默认公共反代池已坏, CF 站全挂。
# 源: KafeMars/best-ips-domains BestProxyIPs; 按实测耗时排序, 前 5 个入池轮换。
# 注意: ProxyIP 只影响「目标也是 CF 站」的连接, 非 CF 站 (google 等) 不经中转、不受影响。
PROXYIP_POOL = [
    "38.65.9.111",       # LAX, 1.8s
    "38.58.108.84",      # LAX, 2.0s
    "64.49.28.173",      # LAX, 1.9s
    "23.246.155.195",    # SJC, 2.1s
    "160.16.103.102",    # NRT, 2.8s
]
_PROXYIP_CURSOR = [0]


def _next_proxyip():
    """轮换分配 ProxyIP, 单点失效只影响部分节点。"""
    i = _PROXYIP_CURSOR[0]
    _PROXYIP_CURSOR[0] = i + 1
    return PROXYIP_POOL[i % len(PROXYIP_POOL)]

CF_IP_FALLBACK = [
    "104.18.58.130:443",
    "104.18.54.222:443",
    "162.159.237.185:443",
    "104.17.170.218:443",
]
# Cloudflare 官方网段白名单: 源被污染时不至于把第三方 VPS 混进入口池
CF_CIDRS = [
    "104.16.0.0/13", "104.24.0.0/14", "104.31.0.0/16",
    "172.64.0.0/13", "188.114.96.0/20", "162.159.0.0/16",
    "198.41.128.0/17", "23.235.32.0/20", "69.171.224.0/19",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
]
_preferred_ip_cache = None
_preferred_domain_cache = None


def _is_cloudflare_ip(addr: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(c) for c in CF_CIDRS)


def _parse_entry_lines(text, require_cf_ip=False):
    """解析源文件的 host:port#备注 行。
    返回 [(host:port, country, remark), ...]; 缺端口按 443 补, 非 CF 网段直接丢弃。"""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "://" in line:
            continue
        addr, _, remark = line.partition("#")
        addr = addr.strip()
        if not addr:
            continue
        host, sep, port = addr.partition(":")
        host = host.strip()
        port = port.strip()
        if not sep or not port:
            port = "443"
        if not port.isdigit():
            continue
        if require_cf_ip and not _is_cloudflare_ip(host):
            continue
        # 国家标记: 源文件格式各异 (US 🇺🇸 / 🇳🇱 荷兰-01 / 【日本】), 统一取可识别的国家 token
        country = ""
        for token in remark.replace("【", " ").replace("】", " ").split():
            t = token.strip("-—·,，")
            if len(t) == 2 and t.isalpha() and t.isupper():
                country = t
                break
        entries.append((f"{host}:{port}", country, remark))
    return entries


def _pick_diverse(entries, limit):
    """先按国家分散挑选(每个国家一条), 不足再按原顺序补齐。
    源文件常按国家分组, 不做分散会整批落在同一地区。"""
    picked = []
    used = set()
    for addr, country, _ in entries:
        if country and country in used:
            continue
        picked.append(addr)
        if country:
            used.add(country)
        if len(picked) >= limit:
            return picked
    for addr, _, _ in entries:
        if addr not in picked:
            picked.append(addr)
        if len(picked) >= limit:
            break
    return picked


# 运营商分线关键词: 源文件里带这些标记的域名是针对国内三网分别优化过的
_CARRIER_TAGS = ("三网", "电信", "移动", "联通", "ctcc", "cmcc", "cucc")
# 具体运营商分线 (只对单一运营商优选, 换网络就可能失效)
_CARRIER_SPECIFIC = ("电信", "移动", "联通", "ctcc", "cmcc", "cucc")


def _pick_domains(entries, limit):
    """域名源挑选优先级:
      0 = 通用三网分线 (标注「三网」, 对所有运营商都优选)   <- 最稳
      1 = 具体运营商分线 (只对单一运营商优选)
      2 = 其他通用优选域名
    实测三网分线域名波动比优选 IP 大, 所以只取少数几个, 主力仍靠优选 IP。"""
    def tier(e):
        addr, _, remark = e
        generic = "三网" in remark or "all" in remark.lower()
        specific = any(t in remark for t in _CARRIER_SPECIFIC) or \
            any(t in addr for t in ("ctcc", "cmcc", "cucc"))
        if generic:
            return 0
        if specific:
            return 1
        return 2

    picked = []
    for addr, _, _ in sorted(entries, key=tier):
        if addr not in picked:
            picked.append(addr)
        if len(picked) >= limit:
            break
    return picked


def _fetch_text(url, tries=3):
    """拉取源文件; raw.githubusercontent 偶发 ProxyError/超时, 重试几次。
    raw.github.com 抖动时自动切 jsDelivr 镜像 (CDN 加速, 内容同源)。"""
    candidates = [url]
    m = re.match(r"^https://raw\.githubusercontent\.com/([^/]+/[^/]+)/([^/]+)/(.+)$", url)
    if m:
        candidates.append(f"https://cdn.jsdelivr.net/gh/{m.group(1)}@{m.group(2)}/{m.group(3)}")
    last = None
    for i in range(tries):
        for cand in candidates:
            try:
                resp = requests.get(cand, timeout=(10, 30))
                resp.raise_for_status()
                if resp.text.strip():
                    return resp.text
                last = "空响应"
            except Exception as e:
                last = f"{type(e).__name__}"
        if i < tries - 1:
            time.sleep(1.5 * (i + 1))
    print(f"[源] {url.rsplit('/', 1)[-1]} 拉取失败({last})")
    return ""


def _fetch_from_sources(sources, limit, require_cf_ip, label, picker=None):
    """依次尝试各源, 第一个成功返回足够条目的源即采用。"""
    picker = picker or _pick_diverse
    for url in [u.strip() for u in sources.split(",") if u.strip()]:
        text = _fetch_text(url)
        if not text:
            continue
        entries = _parse_entry_lines(text, require_cf_ip=require_cf_ip)
        if not entries:
            print(f"[{label}] 源无可用条目, 换下一个: {url}")
            continue
        picked = picker(entries, limit)
        print(f"[{label}] 源 {url.rsplit('/', 2)[-2]}/{url.rsplit('/', 1)[-1]} "
              f"可用 {len(entries)} 条 -> 选 {len(picked)} 条")
        return picked
    return []


def fetch_preferred_ips():
    """拉取优选 IP 清单; 失败或全部被白名单过滤时回退到内置列表。"""
    global _preferred_ip_cache
    if _preferred_ip_cache is not None:
        return _preferred_ip_cache
    ips = []
    if CF_IP_LIMIT > 0 and CF_IP_SOURCE:
        ips = _fetch_from_sources(CF_IP_SOURCE, CF_IP_LIMIT, True, "优选IP")
    if not ips:
        ips = [x for x in CF_IP_FALLBACK][:CF_IP_LIMIT]
        print(f"[优选IP] 使用内置兜底: {', '.join(ips)}")
    else:
        print(f"[优选IP] 选中 {len(ips)} 条: {', '.join(ips)}")
    _preferred_ip_cache = ips
    return ips


def fetch_verified_ips():
    """本机实测验证过的优选 IP (CloudflareSpeedTest 本机跑 + 端到端二次验证的结果)。"""
    return [ip for ip, _ in VERIFIED_IPS]


def fetch_preferred_domains():
    """拉取优选域名清单 (源里的域名是别人网络下测的, 本机普遍很慢, 只作补充)。
    前面先放本机实测验证过的域名 (VERIFIED_DOMAINS), 按实测速度排序。"""
    global _preferred_domain_cache
    if _preferred_domain_cache is not None:
        return _preferred_domain_cache
    domains = []
    if CF_DOMAIN_LIMIT > 0 and CF_DOMAIN_SOURCE:
        domains = _fetch_from_sources(CF_DOMAIN_SOURCE, CF_DOMAIN_LIMIT, False,
                                      "优选域名", picker=_pick_domains)
    verified = [d for d, _ in VERIFIED_DOMAINS]
    merged = verified + [d for d in domains if d not in verified]
    _preferred_domain_cache = merged
    print(f"[优选域名] 池 = 本机实测 {len(verified)} 个 + 外部源 {len(domains)} 个")
    return merged


def build_entry_pool(env_name: str, fallback):
    """入口池 = 环境变量指定的入口 + 本机实测域名 + 本机实测优选 IP + 外部源(兜底)。

    实测结论(2026-10-23, 串行 3 轮端到端真实出站):
      - 域名型入口跨轮速度极差远小于 IP 型入口 (speedtest 2.54 vs 现用 IP 最高 1.85)
      - 本机实测的 6 个优选 IP (SJC/LAX 段) 稳定在 7.5~10.8 Mbps, 是池子主力
      - 外部源自动拉取的 IP 实测 5/6 直接超时, 只剩 0.34 Mbps —— 已降级为纯兜底
      - 外部源给的域名普遍只有 0.2~1.4 Mbps, 同样只能当冗余
      - CFST 的下载速度排名对本场景无预测力 (r=0.424), 只有端到端实测过的才能进池
    所以排序上把本机实测过的放前面, 外部源垫底。
    """
    raw = os.environ.get(env_name, "").strip()
    pool = [x.strip() for x in raw.split(",") if x.strip()] or list(fallback)
    # fetch_preferred_domains 已返回「本机实测域名 + 外部源域名」的合并列表
    for d in fetch_preferred_domains():
        if d not in pool:
            pool.append(d)
    for ip in fetch_verified_ips():
        if ip not in pool:
            pool.append(ip)
    for ip in fetch_preferred_ips():
        if ip not in pool:
            pool.append(ip)
    return pool


def build_hosts_text(data):
    """生成可直接粘贴到 edgetunnel 后台「自定义优选IP」框的清单。
    每行 = 入口地址#名字$sstp://... ; 名字固定, 底下 SSTP 节点每 30 分钟自动换。"""
    countries = data["countries"]
    # 入口: 默认用实测可用优选域名循环分配; 可用 HOSTS_ENTRY 覆盖(逗号分隔), 并自动追加优选 IP
    edge = build_entry_pool("HOSTS_ENTRY", EDGE_HOSTS or [f"{EDT_DOMAIN}:443"])
    lines = [
        "# edgetunnel「自定义优选IP」清单 (整段复制, 追加到后台现有内容后面)",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {HOSTS_URL}",
        "# 每行 = 入口地址#名字$sstp://vpn:vpn@节点:端口",
        "# 入口池 = 预设入口 + 本机实测域名 + 外部优选域名 + 优选 IP(国别分散)",
        "# 名字 = 国家-住宅/机房-编号, 直接区分住宅与机房",
        "# 名字固定; 只有 $sstp:// 后面的节点地址每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口必须保留",
        "# ========================================================",
    ]
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel 完整订阅 (vless://) 配置
EDT_UUID = os.environ.get("EDT_UUID", "f2afba09-d83b-43d1-b2df-f149941c4623")
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "vpn.cnzxmdd.cc.cd")
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT", "chrome")
SUB_URL = os.environ.get("SUB_URL", "https://funnyday-py.github.io/ggboom/sub.txt")


def _b64_secret_encode(plaintext, secret):
    """复刻 edgetunnel 的 base64SecretEncode: UTF-8 循环密钥 XOR + 标准 base64。"""
    data = plaintext.encode("utf-8")
    key = secret.encode("utf-8")
    mixed = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return base64.b64encode(mixed).decode("ascii")


def _socks5_account(address, default_port=80):
    """复刻 edgetunnel 的 获取SOCKS5账号: user:pass@host:port -> {username,password,hostname,port}。"""
    address = re.sub(r"^(socks5|http|https|turn|sstp)://", "", address.strip(), flags=re.I).split("#")[0].strip()
    at = address.rfind("@")
    auth, hostpart = (address[:at], address[at + 1:]) if at != -1 else ("", address)
    hostpart = hostpart.split("/")[0]
    username = password = None
    if auth:
        if ":" not in auth:
            try:
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode("utf-8")
            except Exception:
                pass
        parts = auth.split(":", 1)
        username = parts[0]
        password = parts[1] if len(parts) > 1 else None
    hostname, port = hostpart, default_port
    if hostpart.count(":") == 1 and not hostpart.startswith("["):
        h, p = hostpart.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)
    return {"username": username, "password": password, "hostname": hostname, "port": port}


def build_sub_text(data):
    """生成 edgetunnel 完整 vless:// 订阅 (链式代理编码在 path)。
    连接地址默认用 Worker 自定义域 (SNI 不再是 workers.dev, 避开 GFW 的 SNI 阻断);
    如需优选入口可设 SUB_ENTRY 环境变量 (逗号分隔 host:port)。"""
    countries = data["countries"]
    _sub_entry = os.environ.get("SUB_ENTRY", "").strip()
    edge = build_entry_pool("SUB_ENTRY", [f"{EDT_DOMAIN}:443"])
    lines = [
        "# edgetunnel 完整订阅 (vless://) —— 填进后台「订阅链接」URL",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {SUB_URL}",
        f"# Worker 域名: {EDT_DOMAIN} (ws / TLS / fingerprint {EDT_FINGERPRINT})",
        f"# 连接地址: {', '.join(edge)}",
        "# 前置 CF直出 组: 不经中继, 延迟最低; 出口为 CF 共享 IP (部分站点风控)",
        "# 其后为链式组: $sstp:// 中继编码在 path, 每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口已编码进 path",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )

    def _parse_entry(entry):
        e_host, e_port = (entry.split(":") + ["443"])[:2]
        if not e_port.isdigit():
            e_host, e_port = entry, "443"
        return e_host, e_port

    def _build_link(n, name, entry):
        """单节点的 vless:// 链接: 连接地址=入口, SNI/Host=Worker 域, 链式参数编码在 path。"""
        chain = {"type": "sstp", **_socks5_account(f"vpn:vpn@{n['host']}:{n['port']}", 443)}
        enc = _b64_secret_encode(json.dumps(chain, separators=(",", ":")), EDT_UUID)
        e_host, e_port = _parse_entry(entry)
        return (
            f"vless://{EDT_UUID}@{e_host}:{e_port}?security=tls&type=ws"
            f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
            f"&path={quote('/video/' + enc, safe='')}&encryption=none&alpn=#{quote(name, safe='')}"
        )

    def _build_direct_link(name, entry):
        """不经 VPN Gate 中继: Worker 用原生 connect() 直连目标, 出口是 Cloudflare 的 IP。
        path 里 proxyip= 填实测可用中转 (PROXYIP_POOL 轮换):
        Worker 的 connect() 被平台禁止回连 CF 自家 IP (防回环), 直接访问
        *.cloudflare.com 等 CF 前置站必然「隧道断开」(ERR_CONNECTION_CLOSED, 2026-10-24 实测);
        填了 ProxyIP 后 CF 站经非 CF 中转可达, 非 CF 站 (google 等) 不受影响。
        留空则走默认公共反代池 —— 该池实测已坏, 等于 CF 站全挂。"""
        e_host, e_port = _parse_entry(entry)
        pip = _next_proxyip()
        return (
            f"vless://{EDT_UUID}@{e_host}:{e_port}?security=tls&type=ws"
            f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
            f"&path={quote('/?ed=2048&proxyip=' + pip, safe='')}&encryption=none&alpn=#{quote(name, safe='')}"
        )

    # CF 直出组: 不走中继, 握手最快; 出口是 Cloudflare 共享 IP (部分站点会风控)
    lines.append("")
    lines.append("# ---- CF 直出 (不经 SSTP 中继; 延迟最低, 但出口是 Cloudflare 共享 IP, 部分站点会风控) ----")
    for i, e in enumerate(edge, 1):
        lines.append(_build_direct_link(f"CF直出-{i:02d}", e))

    # CF 直出扩展组: 用实测优选 IP 为每个节点生成直出链接。
    # 起因 (2026-10-23): VPN Gate 的 opengw.net 中继批量失效 (DNS 还解析得到 AWS IP 54.76.135.1,
    # 但 TCP 全超时), 链式组 0/20 可用; 此时直出是唯一能用的组, 需要足够的节点量顶替。
    # 用实测最优的 VERIFIED_IPS 循环分配, 保证每条链路都有 7~10 Mbps 的入口。
    verified_ips = fetch_verified_ips()
    if verified_ips:
        lines.append("")
        lines.append("# ---- CF 直出扩展 (用本机实测优选 IP, 链式中继失效时的主力) ----")
        all_direct_nodes = [n for grp in countries.values() for n in grp["nodes"]]
        for i, n in enumerate(all_direct_nodes, 1):
            e = verified_ips[(i - 1) % len(verified_ips)]
            code = str(n.get("country_code") or "").upper()
            zh = COUNTRY_ZH.get(code) or code or "节点"
            lines.append(_build_direct_link(f"直出扩展-{zh}-{i:02d}", e))

    # 极速组: 按链路握手延迟升序取前 8 个, 不分国家/住宅机房 (追求速度优先用这组)
    all_nodes = [n for grp in countries.values() for n in grp["nodes"]]
    fastest = sorted(
        all_nodes, key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n.get("host") or "")
    )[:8]
    if fastest:
        lines.append("")
        lines.append("# ---- 极速 TOP8 (握手延迟升序, 不限国家与住宅/机房; 追求速度优先选这组) ----")
        for i, n in enumerate(fastest, 1):
            lines.append(_build_link(n, f"极速-{i:02d}", edge[(i - 1) % len(edge)]))

    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        _idx = 0
        for i, n in enumerate(nodes, 1):
            name = f"{zh}-{i:02d}"
            entry = edge[_idx % len(edge)]
            _idx += 1
            lines.append(_build_link(n, name, entry))
    return "\n".join(lines) + "\n"


def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    # 固定网页: 始终用 web/index.html 模板生成同一个 index.html (数据来自 data.json)
    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = ("<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
                "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
                "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # edgetunnel 链式代理清单 (固定 URL, 方案一: 名字不变、指令自动换)
    chains_path = os.path.join(PUBLIC_DIR, "chains.txt")
    with open(chains_path, "w", encoding="utf-8") as f:
        f.write(build_chains_text(data))

    # 可直接粘贴进后台「自定义优选IP」框的清单 (入口地址#名字$sstp://...)
    hosts_path = os.path.join(PUBLIC_DIR, "hosts.txt")
    with open(hosts_path, "w", encoding="utf-8") as f:
        f.write(build_hosts_text(data))

    # 完整 vless:// 订阅 (填进后台「订阅链接」URL, 客户端自动轮换)
    sub_path = os.path.join(PUBLIC_DIR, "sub.txt")
    with open(sub_path, "w", encoding="utf-8") as f:
        f.write(build_sub_text(data))
    return data_path, html_path, chains_path, hosts_path, sub_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()

    # 1) 数据源
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    # 2) SSTP 筛选 + 去重
    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    # 3) 并发检测
    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    # 硬性失败: Worker 完全不可达 (没有任何一个请求拿到正常响应)
    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    # 4) 结果 + 网页
    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    data_path, html_path, chains_path, hosts_path, sub_path = write_outputs(data)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(chains_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(hosts_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(sub_path, REPO_DIR)}")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
