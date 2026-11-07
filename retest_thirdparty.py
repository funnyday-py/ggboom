#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""第三方反代 IP 候选复测 (不花钱路线的第一步)。

背景: 2026-11-06 调研 CF-APEX 时, 234 条内置第三方 VPS 反代 IP 抽样 10 条,
只有 5 条可用、中位 0.35 Mbps, 但 117.55.232.78 三轮 2.79/4.37/4.20 Mbps 稳定。
第三方 VPS 没有 SLA, 衰减极快 (同批 14 个公益中继域名 5/6 DNS 已失效),
所以**不能把昨天的单次结论直接写进生产入口池**。本脚本在真正纳入前重测一遍。

口径与 probe_entries.py 一致:
  - 连通性 = 完整链路 TCP -> TLS(SNI=Worker域) -> WS 101 -> VLESS 头 -> 隧道内 TLS 握手
  - 速度 = 隧道内下载 2MB, 串行测 (并发会互抢带宽, 测出来没有可比性)
  - 对照组 = 我们现役的 CF 官方 Anycast 段, 同一时刻同一路径, 才具备可比性

产物 thirdparty_probe.json 只作为**本次决策依据**, 生产入口池由 vpngate.py 的
THIRD_PARTY_ENTRIES 显式清单控制, 不会自动把这里测出来的 IP 全量收编。

用法:
    python retest_thirdparty.py                 # 默认抽样 (每区 5 条)
    python retest_thirdparty.py --per-region 10
    python retest_thirdparty.py --entries 1.2.3.4:443,5.6.7.8:8443
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lib

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
APEX_JS = os.path.join(os.path.dirname(REPO_DIR), "cfapex", "w1.2.4.js")
OUT_FILE = os.path.join(REPO_DIR, "thirdparty_probe.json")

PATH = "/?ed=2048&proxyip="
TARGET = "proof.ovh.net"
DOWNLOAD_BYTES = 2 * 1024 * 1024
HANDSHAKE_TIMEOUT = 8
DOWNLOAD_TIMEOUT = 12

# 昨天(2026-11-06)实测最快的那条, 无论抽样怎么取都强制纳入复测
MUST_TEST = ["117.55.232.78:443"]
# 对照组: 现役 CF 官方段 (VERIFIED_IPS 前三个)
CONTROL = ["104.18.58.130:443", "104.18.54.222:443", "162.159.237.185:443"]


def apex_pool(per_region):
    """按地区等距抽样, 避免只测到列表头部那一批 (头部往往最旧、最拥挤)。"""
    if not os.path.exists(APEX_JS):
        print(f"找不到候选源文件: {APEX_JS}", flush=True)
        print("该文件是本地调研留档, 未随仓库提交。可以改用 --entries 直接指定要测的地址,", flush=True)
        print("或查看同目录 thirdparty_probe.json 里已有的实测记录。", flush=True)
        return []
    s = open(APEX_JS, encoding="utf-8", errors="replace").read()
    m = re.search(r"const PREFERRED_LIST = '([^']+)'", s)
    if not m:
        return []
    by_region = {}
    for item in m.group(1).split(","):
        item = item.strip()
        addr, _, name = item.partition("#")
        r = re.match(r"([a-z]{2})", name or "")
        if not r or not addr:
            continue
        by_region.setdefault(r.group(1), []).append(addr.strip())
    picked = []
    for region, addrs in by_region.items():
        if not addrs:
            continue
        n = min(per_region, len(addrs))
        # 等距取样, 且一定含首条 (昨天测过的前两条在首部)
        idx = sorted({0} | {round(i * (len(addrs) - 1) / max(1, n - 1)) for i in range(n)})
        for i in idx[:n]:
            picked.append((region, addrs[i]))
    return picked


def parse_entry(s):
    host, _, port = s.rpartition(":")
    if not host or not port.isdigit():
        return (s, 443)
    return (host, int(port))


def handshake(entry):
    """只判连通, 不下载数据 —— 可以并发, 不受带宽竞争影响。"""
    ws = None
    try:
        ws = probe_lib.WS(PATH, entry=entry, timeout=HANDSHAKE_TIMEOUT)
        tls = probe_lib.TunnelTLS(ws, TARGET)
        ws.send(probe_lib.vless_header(TARGET, 443) + tls.first_flight)
        tls.handshake()
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:40]}"
    finally:
        try:
            if ws and getattr(ws, "s", None):
                ws.s.close()
        except Exception:
            pass


def measure(entry, rounds=2):
    """隧道内下载 2MB 计时; 返回 (中位 Mbps, 明细)。必须串行调用。"""
    vals, notes = [], []
    for _ in range(rounds):
        ws = None
        t0 = time.time()
        try:
            ws = probe_lib.WS(PATH, entry=entry, timeout=HANDSHAKE_TIMEOUT)
            tls = probe_lib.TunnelTLS(ws, TARGET)
            ws.send(probe_lib.vless_header(TARGET, 443) + tls.first_flight)
            tls.handshake()
            tls.send((f"GET /files/10Mb.dat HTTP/1.1\r\nHost: {TARGET}\r\n"
                      "User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode())
            total, head_len, raw, status = 0, 0, b"", None
            t1 = time.time()
            while time.time() - t1 < DOWNLOAD_TIMEOUT:
                try:
                    d = tls.recv()
                except Exception:
                    break
                if not d:
                    break
                total += len(d)
                if status is None:
                    raw += d
                    if b"\r\n\r\n" in raw:
                        head_len = raw.index(b"\r\n\r\n") + 4
                        first = raw.split(b"\r\n", 1)[0].decode("latin1", "replace")
                        status = first.split(" ")[1] if " " in first else first
                if total - head_len >= DOWNLOAD_BYTES:
                    break
            dur = time.time() - t1
            body = max(0, total - head_len)
            if body < 20000:
                notes.append(f"失败: 仅 {body}B / 状态 {status}")
                continue
            mbps = body * 8 / dur / 1e6
            vals.append(mbps)
            notes.append(f"{status} {body // 1024}KB / {dur:.1f}s / {mbps:.2f} Mbps")
        except Exception as e:
            notes.append(f"{type(e).__name__}: {str(e)[:36]}")
        finally:
            try:
                if ws and getattr(ws, "s", None):
                    ws.s.close()
            except Exception:
                pass
        _ = t0
    return (statistics.median(vals) if vals else None), notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-region", type=int, default=5, help="每个地区抽样条数 (默认 5)")
    ap.add_argument("--entries", help="直接指定逗号分隔的 host:port, 跳过抽样")
    ap.add_argument("--rounds", type=int, default=2, help="每个可用入口测速轮数 (默认 2)")
    args = ap.parse_args()

    if args.entries:
        candidates = [("自定义", x.strip()) for x in args.entries.split(",") if x.strip()]
    else:
        candidates = [(r, a) for r, a in apex_pool(args.per_region)]
    # 强制纳入 + 去重
    seen = {a for _, a in candidates}
    for a in MUST_TEST:
        if a not in seen:
            candidates.insert(0, ("重点", a))
            seen.add(a)

    print(f"第三方候选 {len(candidates)} 个 + 对照组 {len(CONTROL)} 个", flush=True)
    print(f"第一步: 并发筛连通性 (8 线程, 只握手不下载)", flush=True)
    print("-" * 78, flush=True)

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        fut = {ex.submit(handshake, parse_entry(a)): (r, a) for r, a in candidates}
        alive = []
        for f in cf.as_completed(fut):
            r, a = fut[f]
            ok, err = f.result()
            if ok:
                alive.append((r, a))
            else:
                print(f"  不通  {a:24s} {err[:44]}", flush=True)

    print(f"连通性: {len(alive)}/{len(candidates)} 可用", flush=True)
    print("-" * 78, flush=True)
    print(f"第二步: 串行测速 (每入口 {args.rounds} 轮 2MB 下载, 对照组同时段)", flush=True)

    rows = []
    for r, a in alive + [("对照组", x) for x in CONTROL]:
        mbps, notes = measure(parse_entry(a), args.rounds)
        rows.append({"region": r, "entry": a, "mbps": round(mbps, 2) if mbps else None,
                     "notes": notes})
        print(f"  {r:6s} {a:24s} "
              f"{('%6.2f Mbps' % mbps) if mbps else '   失败  '}  {notes[-1] if notes else ''}",
              flush=True)

    third = [x["mbps"] for x in rows if x["region"] != "对照组" and x["mbps"]]
    ctrl = [x["mbps"] for x in rows if x["region"] == "对照组" and x["mbps"]]
    print("-" * 78, flush=True)
    if third:
        print(f"第三方: 可用 {len(third)}/{len(alive)}  中位 {statistics.median(third):.2f} Mbps  "
              f"最快 {max(third):.2f}", flush=True)
    else:
        print("第三方: 无可用入口", flush=True)
    if ctrl:
        print(f"对照组: 可用 {len(ctrl)}/{len(CONTROL)}  中位 {statistics.median(ctrl):.2f} Mbps  "
              f"最快 {max(ctrl):.2f}", flush=True)

    data = {
        "generated_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(timespec="seconds"),
        "source": "CF-APEX PREFERRED_LIST (第三方 VPS 反代, 非 CF 官方段)",
        "judge": "本机串行 2MB 下载; 对照组为现役 CF 官方段同时段测试",
        "alive_count": len(alive),
        "candidate_count": len(candidates),
        "summary": {
            "thirdparty_available": len(third),
            "thirdparty_median_mbps": round(statistics.median(third), 2) if third else None,
            "control_available": len(ctrl),
            "control_median_mbps": round(statistics.median(ctrl), 2) if ctrl else None,
        },
        "rows": rows,
    }
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(f"已写 {os.path.relpath(OUT_FILE, REPO_DIR)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
