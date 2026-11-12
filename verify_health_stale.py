#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""验收「健康结论分级过期」策略 (vpngate.load_entry_health)。

旧逻辑: age > ttl 直接返回 {} -> filter_dead_entries 全量不过滤,
       已知判死的入口原地复活。本脚本用临时文件替换 HEALTH_FILE,
       逐场景断言新的降级顺序, 并确认订阅生成不报错。

运行: python verify_health_stale.py
"""
import contextlib
import datetime as dt
import io
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.environ.setdefault("CF_IP_LIMIT", "0")
os.environ.setdefault("CF_DOMAIN_LIMIT", "0")
os.environ.setdefault("SUB_ENTRY", "good.example:443,104.18.58.130:443")
import vpngate as vg

POOL = ["good.example:443", "dead.example:443", "unknown.example:443"]
REAL_PROXY = list(vg.PROXYIP_POOL)
PROXY_STATE = {ip: (i % 2 == 0) for i, ip in enumerate(REAL_PROXY)}
ALIVE_PROXY = [ip for ip in REAL_PROXY if PROXY_STATE[ip]]
ENTRIES = {
    "good.example:443": {"ok": True, "pass": 3, "tries": 3},
    "dead.example:443": {"ok": False, "pass": 0, "tries": 3,
                         "stages": {"downlink_zero": 3}},
}
RESULTS = []


def check(cond, label):
    RESULTS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def make_data(age_h, ttl=24, entries=None, proxyips=None, naive=False):
    tz = dt.timezone(dt.timedelta(hours=8))
    gen = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=age_h)
    stamp = (gen.replace(tzinfo=None) if naive else gen.astimezone(tz)).isoformat(timespec="seconds")
    return {
        "generated_at": stamp,
        "ttl_hours": ttl,
        "judge": "验收用构造数据",
        "strict": True,
        "entries": ENTRIES if entries is None else entries,
        "proxyips": PROXY_STATE if proxyips is None else proxyips,
    }


def run_case(data=None, raw=None, missing=False):
    """把健康数据指向临时文件, 重置模块缓存, 返回 (结论, 输出, 过滤结果, 中转池)。"""
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "entry_health.json")
        if not missing:
            with open(p, "w", encoding="utf-8") as f:
                f.write(raw if raw is not None else json.dumps(data, ensure_ascii=False))
        old_file, old_cache = vg.HEALTH_FILE, vg._health_cache
        vg.HEALTH_FILE, vg._health_cache = p, False
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                h = vg.load_entry_health()
                filtered = vg.filter_dead_entries(list(POOL))
                proxies = vg.alive_proxyips()
        finally:
            vg.HEALTH_FILE, vg._health_cache = old_file, old_cache
        return h, buf.getvalue(), filtered, proxies


print("=" * 74)
print("一、新鲜结论 (1h)")
print("=" * 74)
h, out, filt, px = run_case(make_data(1))
check(bool(h) and h.get("entries") == ENTRIES, "结论正常载入")
check("dead.example:443" not in filt and len(filt) == 2, "判死入口被剔除, 未测入口按可用保留")
check("载入" in out, "输出为正常使用口径")
check(px == ALIVE_PROXY, "判死中转被剔除")

print()
print("=" * 74)
print("二、软过期 —— 核心: 探针没及时跑, 死入口也不能复活")
print("=" * 74)
for age in (30, 167):
    h, out, filt, px = run_case(make_data(age))
    check("dead.example:443" not in filt, f"{age}h: 判死入口仍被剔除 (旧逻辑此处会复活)")
    check("仍沿用" in out, f"{age}h: 打印沿用警告并提示刷新")
    check(px == ALIVE_PROXY, f"{age}h: 判死中转仍被剔除")

print()
print("=" * 74)
print("三、硬过期 (> 硬上限 168h): 放弃旧结论, 全量回退")
print("=" * 74)
h, out, filt, px = run_case(make_data(200))
check(filt == POOL, "入口池不过滤")
check(px == REAL_PROXY, "中转池回退完整")
check("硬过期" in out, "打印硬过期提示")

print()
print("=" * 74)
print("四、异常与冷启动保护 (仍然不过滤)")
print("=" * 74)
h, out, filt, px = run_case(missing=True)
check(filt == POOL and "无 entry_health" in out, "缺文件")
h, out, filt, px = run_case(raw="{ not json")
check(filt == POOL and "读取失败" in out, "非法 JSON")
h, out, filt, px = run_case(make_data(1, entries=[]))
check(filt == POOL and "无有效入口结论" in out, "entries 结构不对")
h, out, filt, px = run_case(make_data(1, entries={}))
check(filt == POOL and "无有效入口结论" in out, "entries 为空")
all_dead = {e: {"ok": False, "pass": 0, "tries": 3} for e in POOL}
h, out, filt, px = run_case(make_data(1, entries=all_dead))
check(filt == POOL and "剔除后入口池为空" in out, "剔空后整体回退")

print()
print("=" * 74)
print("五、时间边界兼容")
print("=" * 74)
h, out, filt, px = run_case(make_data(-2))
check("dead.example:443" not in filt and "时钟" in out, "生成时间在未来: 不崩且仍剔除")
h, out, filt, px = run_case(make_data(1, naive=True))
check("dead.example:443" not in filt, "旧数据无时区标记: 按 UTC 兼容")

print()
print("=" * 74)
print("六、真实健康数据 + 订阅生成")
print("=" * 74)
old_cache = vg._health_cache
vg._health_cache = False
buf = io.StringIO()
try:
    with contextlib.redirect_stdout(buf):
        real = vg.load_entry_health()
        fake = {"generated_at": "2026-11-12 12:00:00",
                "countries": {"JP": {"code": "JP", "count": 1, "nodes": [
                    {"host": "1.2.3.4", "port": 443, "country_code": "JP",
                     "latency_ms": 100, "residential": "residential"}]}}}
        txt = vg.build_sub_text(fake)
finally:
    vg._health_cache = old_cache
check(bool(real) and len(real.get("entries", {})) > 0, "仓库真实 entry_health.json 能载入")
check(sum(l.startswith("vless://") for l in txt.splitlines()) > 0, "订阅生成不报错且有节点")
check("结论已过期" not in buf.getvalue(), "当前数据仍在有效期内")

print()
print("=" * 74)
print(f"合计 {sum(RESULTS)}/{len(RESULTS)} 通过 | 硬上限 {vg.HEALTH_HARD_EXPIRE_HOURS:.0f}h")
print("=" * 74)
sys.exit(0 if all(RESULTS) else 1)
