#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""验收「健康结论分级过期」策略 (vpngate.load_entry_health) 与订阅下发过滤。

旧逻辑: age > ttl 直接返回 {} -> filter_dead_entries 全量不过滤,
       已知判死的入口原地复活。

2026-11-12 独立评审后的三处修正:
  1. 硬过期已改为「只保留负面结论」。原验收脚本却断言 filt == POOL
     (死入口全量复活) 为 PASS, 等于把 bug 固化成绿灯; 现改为断言死入口仍被剔除。
  2. 时钟冻结到固定时刻, 不再读仓库里真实 entry_health.json 的生成时间。
     原第六节「当前数据仍在有效期内」隔天必然假红。
  3. 补订阅生成的负向 + 正向对照用例, 证明判死地址确实不出现在 sub.txt 里,
     且测试本身有鉴别力 (不过滤时该地址会出现), 不是「永远不含」的假绿。

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
DEAD_PROXY = [ip for ip in REAL_PROXY if not PROXY_STATE[ip]]
ENTRIES = {
    "good.example:443": {"ok": True, "pass": 3, "tries": 3},
    "dead.example:443": {"ok": False, "pass": 0, "tries": 3,
                         "stages": {"downlink_zero": 3}},
}
RESULTS = []

# 冻结「当前时刻」, 让 age 精确等于构造值, 可以稳定测 168h 边界。
NOW = dt.datetime(2026, 11, 12, 12, 0, 0, tzinfo=dt.timezone.utc)


class FrozenDatetime(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz is not None else NOW


def check(cond, label):
    RESULTS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def make_data(age_h, ttl=24, entries=None, proxyips=None, naive=False):
    tz = dt.timezone(dt.timedelta(hours=8))
    gen = NOW - dt.timedelta(hours=age_h)
    stamp = (gen.replace(tzinfo=None) if naive else gen.astimezone(tz)).isoformat(timespec="seconds")
    return {
        "generated_at": stamp,
        "ttl_hours": ttl,
        "judge": "验收用构造数据",
        "strict": True,
        "entries": ENTRIES if entries is None else entries,
        "proxyips": PROXY_STATE if proxyips is None else proxyips,
    }


@contextlib.contextmanager
def health_env(data=None, raw=None, missing=False):
    """把健康数据指向临时文件, 冻结时钟, 重置缓存; 退出时完整还原模块状态。"""
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "entry_health.json")
        if not missing:
            with open(p, "w", encoding="utf-8") as f:
                f.write(raw if raw is not None else json.dumps(data, ensure_ascii=False))
        old = (vg.HEALTH_FILE, vg._health_cache, vg.datetime)
        vg.HEALTH_FILE, vg._health_cache, vg.datetime = p, False, FrozenDatetime
        try:
            yield p
        finally:
            vg.HEALTH_FILE, vg._health_cache, vg.datetime = old


def run_case(data=None, raw=None, missing=False):
    """返回 (结论, 输出, 过滤结果, 中转池)。"""
    buf = io.StringIO()
    with health_env(data=data, raw=raw, missing=missing):
        with contextlib.redirect_stdout(buf):
            h = vg.load_entry_health()
            filtered = vg.filter_dead_entries(list(POOL))
            proxies = vg.alive_proxyips()
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
for age in (30, 167, 168):
    h, out, filt, px = run_case(make_data(age))
    check("dead.example:443" not in filt, f"{age}h: 判死入口仍被剔除 (旧逻辑此处会复活)")
    check("仍沿用" in out, f"{age}h: 打印沿用警告并提示刷新")
    check(px == ALIVE_PROXY, f"{age}h: 判死中转仍被剔除")
    check(h.get("expired") is not True, f"{age}h: 未进入硬过期分支 (168h 为边界, 用严格大于)")
check(vg.HEALTH_HARD_EXPIRE_HOURS == 168, "硬上限默认 168h, 与 check.yml 注释口径一致")

print()
print("=" * 74)
print("三、硬过期 (> 硬上限): 只保留负面结论, 死入口不复活")
print("=" * 74)
for age in (169, 200):
    h, out, filt, px = run_case(make_data(age))
    check("dead.example:443" not in filt, f"{age}h: 判死入口仍被剔除 (修正点: 原脚本此处断言复活)")
    check(px == ALIVE_PROXY and not any(ip in px for ip in DEAD_PROXY),
          f"{age}h: 判死中转仍被剔除")
    check(h.get("expired") is True and "硬过期" in out, f"{age}h: 标记 expired 并打印硬过期提示")
    check(set(h.get("entries", {})) == {"dead.example:443"} and "good.example:443" in filt,
          f"{age}h: 判活结论降级为未知, 只留负面结论 (避免误判被无限期锁死)")
h, out, filt, px = run_case(make_data(300, ttl=200))
check(h.get("expired") is not True and "硬上限联动" in out and "dead.example:443" not in filt,
      "自定义 ttl=200h 时硬上限联动到 400h, 300h 仍按软过期沿用")
h, out, filt, px = run_case(make_data(500, ttl=200))
check(h.get("expired") is True and "dead.example:443" not in filt,
      "超过联动后的硬上限 (500h > 400h) 才进入硬过期, 死入口仍不复活")

print()
print("=" * 74)
print("四、异常与冷启动保护 (仍然不过滤; 解析失败要有 CI 警告)")
print("=" * 74)
for label, kw, needle in (
    ("缺文件", dict(missing=True), "无 entry_health"),
    ("非法 JSON", dict(raw="{ not json"), "读取失败"),
    ("entries 结构不对", dict(data=make_data(1, entries=[])), "无有效入口"),
    ("entries 为空", dict(data=make_data(1, entries={})), "无有效入口"),
    ("ttl_hours 非正数", dict(data=make_data(1, ttl=0)), "字段异常"),
):
    h, out, filt, px = run_case(**kw)
    check(filt == POOL and needle in out, label)
    if label != "缺文件":
        check("::warning title=entry_health.json::" in out,
              f"{label}: 在 GitHub Actions 打警告注解, 不静默通过")

dirty = {**ENTRIES, "unknown.example:443": None, "null.example:443": "bad"}
h, out, filt, px = run_case(make_data(1, entries=dirty))
check("dead.example:443" not in filt and "unknown.example:443" in filt,
      "单条结论非字典时不崩, 按未知=可用处理, 判死项仍剔除")
h, out, filt, px = run_case(make_data(1, proxyips={ip: None for ip in REAL_PROXY}))
check(px == REAL_PROXY, "中转结论为 null 时按未知处理, 不误剔整个中转池")
all_dead = {e: {"ok": False, "pass": 0, "tries": 3} for e in POOL}
h, out, filt, px = run_case(make_data(1, entries=all_dead))
check(filt == POOL and "剔除后入口池为空" in out, "剔空后整体回退, 不生成空订阅")

print()
print("=" * 74)
print("五、缓存与时钟兼容")
print("=" * 74)
buf = io.StringIO()
with health_env(make_data(1)):
    with contextlib.redirect_stdout(buf):
        a = vg.load_entry_health()
        b = vg.load_entry_health()
    check(a is b, "重载间隔内复用缓存, 不重复读文件")
    a["_loaded_at"] = 0
    with contextlib.redirect_stdout(buf):
        c = vg.load_entry_health()
    check(c is not a and c.get("entries") == ENTRIES,
          "超过重载间隔后重新计算 age/过期, 缓存不锁死")
# 失败态不写缓存: 补好文件后下一次调用要能读到新结论
with tempfile.TemporaryDirectory() as td:
    p = os.path.join(td, "entry_health.json")
    old = (vg.HEALTH_FILE, vg._health_cache, vg.datetime)
    with open(p, "w", encoding="utf-8") as f:
        f.write("{ not json")
    vg.HEALTH_FILE, vg._health_cache, vg.datetime = p, False, FrozenDatetime
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            bad = vg.load_entry_health()
        with open(p, "w", encoding="utf-8") as f:
            json.dump(make_data(1), f, ensure_ascii=False)
        with contextlib.redirect_stdout(io.StringIO()):
            good = vg.load_entry_health()
    finally:
        vg.HEALTH_FILE, vg._health_cache, vg.datetime = old
    check(not bad and good.get("entries") == ENTRIES,
          "解析失败不写缓存, 文件补好后下一次调用能重新载入")

h, out, filt, px = run_case(make_data(-2))
check("dead.example:443" not in filt and "时钟" in out, "生成时间在未来: 不崩且仍剔除")
h, out, filt, px = run_case(make_data(1, naive=True))
check("dead.example:443" not in filt, "旧数据无时区标记: 按 UTC 兼容")

print()
print("=" * 74)
print("六、订阅生成: 判死地址不进 sub.txt (带正向对照)")
print("=" * 74)
DEAD_IP = vg.VERIFIED_IPS[0][0]
DEAD_HOST = DEAD_IP.split(":")[0]
FAKE_COUNTRIES = {
    "JP": {"code": "JP", "count": 2, "nodes": [
        {"host": "1.2.3.4", "port": 443, "country_code": "JP",
         "latency_ms": 100, "residential": "residential"},
        {"host": "1.2.3.5", "port": 443, "country_code": "JP",
         "latency_ms": 120, "residential": "datacenter"},
    ]},
    "US": {"code": "US", "count": 2, "nodes": [
        {"host": "5.6.7.8", "port": 995, "country_code": "US",
         "latency_ms": 90, "residential": "residential"},
        {"host": "5.6.7.9", "port": 1194, "country_code": "US",
         "latency_ms": 150, "residential": "datacenter"},
    ]},
}
FAKE_DATA = {"generated_at": "2026-11-12 12:00:00", "countries": FAKE_COUNTRIES}
HEALTH_DEAD = make_data(1, entries={
    DEAD_IP: {"ok": False, "pass": 0, "tries": 3, "stages": {"downlink_zero": 3}},
    "good.example:443": {"ok": True, "pass": 3, "tries": 3},
}, proxyips={ip: True for ip in REAL_PROXY})
HEALTH_ALIVE = make_data(1, entries={
    DEAD_IP: {"ok": True, "pass": 3, "tries": 3},
    "good.example:443": {"ok": True, "pass": 3, "tries": 3},
}, proxyips={ip: True for ip in REAL_PROXY})


def build_sub(health, patch_pool=None):
    """在指定健康数据下生成订阅, 返回 (文本, 全部 vless 链接, 各链接的连接地址)。"""
    buf = io.StringIO()
    with health_env(health):
        orig = vg.build_entry_pool
        if patch_pool is not None:
            vg.build_entry_pool = patch_pool
        try:
            with contextlib.redirect_stdout(buf):
                txt = vg.build_sub_text(FAKE_DATA)
        finally:
            vg.build_entry_pool = orig
    links = [l for l in txt.splitlines() if l.startswith("vless://")]
    addrs = [l.split("@", 1)[1].split("?", 1)[0] for l in links]
    return txt, links, addrs


txt, links, addrs = build_sub(HEALTH_DEAD)
head_line = next((l for l in txt.splitlines() if l.startswith("# 连接地址:")), "")
check(len(links) > 0 and "直出-CF站" in txt, "订阅生成成功且 CF站组仍在 (排除整体回退造成的假通过)")
check(DEAD_IP not in addrs, f"判死地址 {DEAD_IP} 不出现在任何 vless 链接里")
check(DEAD_HOST not in head_line, "头部「连接地址」也不列判死地址 (与链接口径一致)")
txt2, links2, addrs2 = build_sub(HEALTH_ALIVE)
check(DEAD_IP in addrs2 or DEAD_HOST in next(
    (l for l in txt2.splitlines() if l.startswith("# 连接地址:")), ""),
    "正向对照: 同一地址不判死时确实会出现, 证明上面两条断言有鉴别力")

# 单独验证 CF站组: 把 edge 固定成不含该地址, 链接只可能来自 verified_ips
fixed_pool = lambda env, fallback: ["good.example:443"]
txt3, _, addrs3 = build_sub(HEALTH_DEAD, patch_pool=fixed_pool)
cf_lines = []
in_cf = False
for line in txt3.splitlines():
    if line.startswith("# ---- 直出-CF站"):
        in_cf = True
        continue
    if in_cf and line.startswith("# ----"):
        break
    if in_cf and line.startswith("vless://"):
        cf_lines.append(line)
cf_addrs = [l.split("@", 1)[1].split("?", 1)[0] for l in cf_lines]
check(len(cf_lines) > 0 and DEAD_IP not in cf_addrs and DEAD_HOST not in cf_addrs[0],
      "CF站直出组本身也过健康过滤 (edge 固定为无关地址后仍不含判死 IP)")
txt4, _, _ = build_sub(HEALTH_ALIVE, patch_pool=fixed_pool)
cf4 = []
in_cf = False
for line in txt4.splitlines():
    if line.startswith("# ---- 直出-CF站"):
        in_cf = True
        continue
    if in_cf and line.startswith("# ----"):
        break
    if in_cf and line.startswith("vless://"):
        cf4.append(line.split("@", 1)[1].split("?", 1)[0])
check(DEAD_IP in cf4, "CF站组正向对照: 不判死时该 IP 会被分配, 证明过滤确实生效")

print()
print("=" * 74)
print(f"合计 {sum(RESULTS)}/{len(RESULTS)} 通过 | 硬上限 {vg.HEALTH_HARD_EXPIRE_HOURS:.0f}h")
print("=" * 74)
sys.exit(0 if all(RESULTS) else 1)
