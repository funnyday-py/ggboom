#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""本机入口探针: 实测订阅里每个连接地址能不能建立完整的 VLESS-over-WS 隧道。

借鉴 CF-APEX 的 dropDeadNodes 思路, 但把探测**放在本机**而不是 CI:

    GitHub Actions 的 runner 在美国机房, 它到 Cloudflare 边缘几乎必然连通;
    真正决定入口可用性的是「本机 -> CF 边缘」这段 (运营商/GFW/时段相关)。
    在 CI 里测等于测了个必然全绿的结果, 没有任何过滤价值。

所以这里只做**连通性判定**, 不做速度排名: 速度是本机 + 当前时段专属,
写进仓库给 CI 读只会把偶然值固化成错误结论 (参见 CFST r=0.424 的教训)。
产物 entry_health.json 提交到仓库后, vpngate.py 每次生成订阅时读取它,
把明确判死的入口剔除; 未测过的、结论过期的一律按可用处理。

用法:
    python probe_entries.py                 # 抓线上 sub.txt, 测完写 entry_health.json
    python probe_entries.py --push          # 测完并直接提交到 GitHub (下次 workflow 生效)
    python probe_entries.py --entries 1.2.3.4:443,5.6.7.8:443   # 测指定候选 (如第三方 IP)
    python probe_entries.py --ttl-hours 48 # 调整结论有效期 (默认 24h)

判定口径: 每个入口测 3 次, 至少 2 次走通完整链路才算可用 (抗单点抖动)。
完整链路 = TCP -> TLS(SNI=Worker域) -> WS 101 -> VLESS 头 -> 隧道内 TLS 握手。

ProxyIP 中转池另判: 它是 **Worker (CF 机房)** 去连的, 不是本机连的;
用本机 TCP 直连判定会把「GFW 拦了但 Worker 能连」的中转误剔除,
所以改为经已验证入口在隧道里访问 CF 自家站, 拿到 HTTP 200 才算可用。
"""
import argparse
import base64
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time

import probe_lib

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
HEALTH_FILE = os.path.join(REPO_DIR, "entry_health.json")
SUB_URL = "https://funnyday-py.github.io/ggboom/sub.txt"

# 纯直出路径: 判的是入口本身能不能承载本机 -> CF 边缘 -> Worker -> 第三方站
PATH = "/?ed=2048&proxyip="
TARGET = "proof.ovh.net"
TRIES = 3
NEED = 2
TIMEOUT = 8

# 与 vpngate.py 保持一致 (import vpngate 会触发拉数据源, 这里直接读环境变量)
DOMAIN = os.environ.get("EDT_DOMAIN", "vpn.cnzxmdd.cc.cd")
UUID = os.environ.get("EDT_UUID", "f2afba09-d83b-43d1-b2df-f149941c4623")
probe_lib.HOST = DOMAIN
probe_lib.UUID_STR = UUID

# ProxyIP 中转池: 由 Worker (CF 机房) 发起连接, 必须经节点端到端判定, 不能用本机 TCP 判
PROXYIP_POOL = [
    "38.65.9.111", "38.58.108.84", "64.49.28.173",
    "23.246.155.195", "160.16.103.102",
]


def fetch_online_entries():
    """抓线上订阅, 解析出实际下发给客户端的连接地址 (去重、保序)。"""
    import urllib.request
    req = urllib.request.Request(SUB_URL, headers={"User-Agent": "Mozilla/5.0"})
    text = urllib.request.urlopen(req, timeout=25).read().decode("utf-8", "replace")
    out = []
    seen = set()
    for line in text.splitlines():
        m = re.match(r"vless://[^@]+@([^:]+):(\d+)\?", line)
        if not m:
            continue
        key = f"{m.group(1)}:{m.group(2)}"
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def parse_entry(s):
    host, _, port = s.rpartition(":")
    if not host or not port.isdigit():
        return (s, 443)
    return (host, int(port))


def probe_once(entry):
    """完整链路判定; 成功返回 True。不下载数据, 因此不受带宽/并发影响。"""
    ws = None
    try:
        ws = probe_lib.WS(PATH, entry=entry, timeout=TIMEOUT)
        tls = probe_lib.TunnelTLS(ws, TARGET)
        ws.send(probe_lib.vless_header(TARGET, 443) + tls.first_flight)
        tls.handshake()
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:50]}"
    finally:
        try:
            if ws and getattr(ws, "s", None):
                ws.s.close()
        except Exception:
            pass


def probe_proxyip(entry, ip, tries=2):
    """经节点端到端判定 ProxyIP: path 带该中转, 在隧道里访问 CF 自家站, 拿到 200 才算可用。

    口径关键: ProxyIP 是 **Worker (CF 机房)** 去连的, 不是本机连的。
    用本机 TCP 直连判它会把「GFW 拦了但 Worker 能连」的中转误剔除,
    所以必须走完整链路 本机 -> CF 边缘 -> Worker -> ProxyIP -> 目标站。
    测 2 次, 有 1 次 200 即算可用 (宁可留着也别误删)。
    """
    path = f"/?ed=2048&proxyip={ip}"
    notes = []
    for _ in range(tries):
        ws = None
        try:
            ws = probe_lib.WS(path, entry=entry, timeout=TIMEOUT)
            tls = probe_lib.TunnelTLS(ws, "www.cloudflare.com")
            ws.send(probe_lib.vless_header("www.cloudflare.com", 443) + tls.first_flight)
            tls.handshake()
            tls.send((f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\n"
                      "User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode())
            raw = b""
            for _ in range(20):
                d = tls.recv()
                if not d:
                    break
                raw += d
                if b"\r\n\r\n" in raw:
                    break
            head = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
            notes.append(head)
            if " 200 " in head or head.endswith(" 200"):
                return True, head
        except Exception as e:
            notes.append(f"{type(e).__name__}: {str(e)[:40]}")
        finally:
            try:
                if ws and getattr(ws, "s", None):
                    ws.s.close()
            except Exception:
                pass
    return False, notes[-1] if notes else "no response"


def push_to_github():
    """经 GitHub Contents API 提交 entry_health.json (git 协议在本机被阻断)。"""
    p = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        capture_output=True, text=True,
    )
    token = next((l.split("=", 1)[1].strip() for l in p.stdout.splitlines()
                  if l.startswith("password=")), None)
    if not token:
        raise RuntimeError("取不到 GitHub PAT (git credential fill)")

    import urllib.error
    import urllib.request
    repo = "funnyday-py/ggboom"
    api = f"https://api.github.com/repos/{repo}/contents/entry_health.json"
    hdr = {"Authorization": f"Bearer {token}",
           "Accept": "application/vnd.github+json", "User-Agent": "probe-entries"}
    sha = None
    try:
        d = json.loads(urllib.request.urlopen(
            urllib.request.Request(api + "?ref=main", headers=hdr), timeout=25).read())
        sha = d.get("sha")
    except urllib.error.HTTPError:
        pass
    payload = {
        "message": "chore: 更新本机入口实测健康数据 (probe_entries.py)",
        "content": base64.b64encode(open(HEALTH_FILE, "rb").read()).decode(),
        "branch": "main",
    }
    if sha:
        payload["sha"] = sha
    req = urllib.request.Request(api, method="PUT", data=json.dumps(payload).encode(),
                                 headers={**hdr, "Content-Type": "application/json"})
    r = urllib.request.urlopen(req, timeout=30)
    print(f"[push] HTTP {r.status}  entry_health.json 已提交", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--entries", help="逗号分隔的 host:port; 不给则抓线上订阅")
    ap.add_argument("--push", action="store_true", help="测完直接提交到 GitHub")
    ap.add_argument("--ttl-hours", type=int, default=24, help="结论有效期 (默认 24 小时)")
    ap.add_argument("--no-proxyip", action="store_true", help="跳过 ProxyIP 中转池探测")
    args = ap.parse_args()

    if args.entries:
        entries = [x.strip() for x in args.entries.split(",") if x.strip()]
        print(f"指定候选 {len(entries)} 个", flush=True)
    else:
        entries = fetch_online_entries()
        print(f"线上订阅抓到 {len(entries)} 个不同入口", flush=True)
    if not entries:
        print("没有可测的入口", file=sys.stderr)
        return 1
    if len(entries) > 40:
        print(f"入口过多 ({len(entries)}), 只测前 40 个", flush=True)
        entries = entries[:40]

    print(f"口径: 每入口 {TRIES} 次, >={NEED} 次走通完整 VLESS-WS-TLS 隧道才算可用; 串行测", flush=True)
    print("-" * 78, flush=True)
    results = {}
    for e in entries:
        oks, errs, t0 = 0, [], time.time()
        for _ in range(TRIES):
            ok, err = probe_once(parse_entry(e))
            if ok:
                oks += 1
            else:
                errs.append(err)
        alive = oks >= NEED
        results[e] = {"ok": alive, "pass": oks, "tries": TRIES, "errors": errs[:2]}
        print(f"  {'可用' if alive else '剔除'}  {e:32s}  {oks}/{TRIES}  "
              f"{time.time()-t0:4.1f}s  {errs[0] if errs else ''}", flush=True)

    proxyips = {}
    if not args.no_proxyip:
        print("-" * 78, flush=True)
        base = next((parse_entry(e) for e, v in results.items() if v["ok"]), None)
        if base is None:
            print("入口全挂, 跳过 ProxyIP 判定 (没有可用基准入口)", flush=True)
        else:
            print(f"ProxyIP 中转池经节点端到端判定 (基准入口 {base[0]}:{base[1]}):", flush=True)
            for ip in PROXYIP_POOL:
                ok, note = probe_proxyip(base, ip)
                proxyips[ip] = ok
                print(f"  {'可用' if ok else '剔除'}  {ip:18s}  {note[:60]}", flush=True)

    data = {
        "generated_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(timespec="seconds"),
        "ttl_hours": args.ttl_hours,
        "judge": "本机连通性判定 (VLESS-WS 隧道内 TLS 握手); 不做速度排名",
        "tries": TRIES,
        "need": NEED,
        "entries": results,
        "proxyips": proxyips,
    }
    with open(HEALTH_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.write("\n")
    n_ok = sum(1 for v in results.values() if v["ok"])
    print("-" * 78, flush=True)
    print(f"结果: 入口 {n_ok}/{len(results)} 可用; 中转 {sum(proxyips.values())}/{len(proxyips)} 可用")
    print(f"已写 {os.path.relpath(HEALTH_FILE, REPO_DIR)} (有效期 {args.ttl_hours}h)", flush=True)

    if args.push:
        push_to_github()
    else:
        print("加 --push 可直接提交到仓库, 下次 workflow 生效", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
