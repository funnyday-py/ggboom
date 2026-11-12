#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""分层严格校验的本地单测: 用假 WS 帧复现四类「假活」, 并与旧口径对比。

不联网、不依赖真实 Worker, 全部用内存里的字节串跑, 因此可以随时回归。

覆盖:
  1. 伪 101 (Sec-WebSocket-Accept 不符 / 状态行蒙混 / 缺 Connection)  —— 旧口径漏判
  2. WS 101 合法但下行零字节                        —— 旧口径靠超时兜底, 无归因
  3. VLESS 响应头 version 非法 / 剥完不是 TLS 记录     —— 旧口径漏判
  4. 正常链路 00 00 + TLS Handshake                  —— 新旧都应通过
  5. probe_link 成功路径与各失败阶段的结论字段         —— 不抛异常, 失败也带阶段
  6. 非严格模式回归: 旧接口行为完全不变

2026-11-12 复核: 原版有两处 check(True, ...) 恒为真, 属于「假绿」——
它只是把漏判基线写成一句话, 断言本身永远通过, 改坏代码也不会变红。
现已改成对旧口径返回值的真实断言, 并补齐 probe_link 的成功路径。

运行: python verify_probe_strict.py
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lib as P

PASS, FAIL = [], []


def check(cond, label):
    (PASS if cond else FAIL).append(label)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def raises(fn, stage=None):
    try:
        fn()
        return False
    except P.ProbeError as e:
        return stage is None or e.stage == stage
    except Exception:
        return False


class FakeSock:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeWS:
    """只实现 _pull / probe_link 需要的 recv/send/status/s, 帧可预置为字节或异常。"""

    def __init__(self, *frames, status="HTTP/1.1 101 Switching Protocols"):
        self.frames = list(frames)
        self.sent = []
        self.status = status
        self.headers = {}
        self.s = FakeSock()

    def recv(self, maxn=262144):
        if not self.frames:
            return b""
        f = self.frames.pop(0)
        if isinstance(f, BaseException):
            raise f
        return f

    def send(self, data):
        self.sent.append(data)


TLS_HELLO = b"\x16\x03\x03\x04\xba" + b"\x02\x00\x04\xb6" + b"\x03\x03" + b"\x00" * 40


def valid_head(key, accept=None):
    a = accept if accept is not None else P.ws_accept(key)
    return (f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Connection: upgrade\r\nUpgrade: websocket\r\n"
            f"Sec-WebSocket-Accept: {a}\r\nServer: cloudflare\r\n").encode()


print("=" * 74)
print("一、WS 升级头 (RFC 6455)")
print("=" * 74)
key = "dGhlIHNhbXBsZSBub25jZQ=="
head = valid_head(key)
status, hdrs = P.parse_ws_upgrade(head, key, strict=True)
check(" 101 " in status and hdrs.get("upgrade") == "websocket", "合法 101 严格校验通过")
check("sec-websocket-accept" in hdrs, "能取到 Sec-WebSocket-Accept 供比对")

# 漏判基线必须是真断言: 证明旧口径确实会返回成功, 而不是写一句 check(True, ...)
bad = valid_head(key, accept="AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
old_status, old_hdrs = P.parse_ws_upgrade(bad, key, strict=False)
check("101" in old_status and old_hdrs.get("sec-websocket-accept") != P.ws_accept(key),
      "旧口径确实放过 Accept 不符的伪 101 (漏判基线)")
check(raises(lambda: P.parse_ws_upgrade(bad, key, strict=True), "ws_upgrade"),
      "伪 101 被严格校验拦在 ws_upgrade")

no_upgrade = head.replace(b"Upgrade: websocket", b"X-Other: websocket")
check(raises(lambda: P.parse_ws_upgrade(no_upgrade, key, strict=True), "ws_upgrade"),
      "缺 Upgrade: websocket 被拦")
no_conn = head.replace(b"Connection: upgrade", b"X-Other: upgrade")
check(raises(lambda: P.parse_ws_upgrade(no_conn, key, strict=True), "ws_upgrade"),
      "缺 Connection: Upgrade 被拦")
no_accept = head.replace(f"Sec-WebSocket-Accept: {P.ws_accept(key)}".encode(),
                         b"Server: cloudflare")
check(raises(lambda: P.parse_ws_upgrade(no_accept, key, strict=True), "ws_upgrade"),
      "缺 Sec-WebSocket-Accept 被拦")

fake_status = b"HTTP/1.1 404 Not Found (ref 1013)\r\nUpgrade: websocket\r\n" \
              b"Connection: Upgrade\r\n" + f"Sec-WebSocket-Accept: {P.ws_accept(key)}\r\n".encode()
old_status, _ = P.parse_ws_upgrade(fake_status, key, strict=False)
check("101" in old_status and not old_status.startswith("HTTP/1.1 101 "),
      "旧口径靠 '101' 子串放过 404 错误页 (漏判基线)")
check(raises(lambda: P.parse_ws_upgrade(fake_status, key, strict=True), "ws_upgrade"),
      "非 101 状态行被严格校验拦住")
non_http = b"ICY 101 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
check(raises(lambda: P.parse_ws_upgrade(non_http, key, strict=True), "ws_upgrade"),
      "非 HTTP/1.x 状态行被拦")

print()
print("=" * 74)
print("二、VLESS 响应头内容")
print("=" * 74)
need, rest, hdr = P.check_vless_response(b"\x00\x00" + TLS_HELLO)
check(need == 2 and hdr.hex() == "0000" and rest[:1] == b"\x16",
      "00 00 + TLS Handshake 通过 (返回 need / 剥离数据 / 头字节)")
need, rest, hdr = P.check_vless_response(b"\x00")
check(need == 2 and hdr == b"", "首帧分片只到 1 字节时等待补齐, 不误判")

check(raises(lambda: P.check_vless_response(b"\x09\x00" + TLS_HELLO), "vless_response"),
      "version=9 被拦 (旧口径会盲目剥离并放行)")
check(raises(lambda: P.check_vless_response(b"\x00\x00<html>error</html>"), "vless_response"),
      "剥完是 HTML 错误页被拦 (旧口径会喂给 TLS BIO)")
check(raises(lambda: P.check_vless_response(b"\x00\xff" + TLS_HELLO), "vless_response"),
      "addons_len=255 异常偏大被拦 (阈值 64, 正常实测为 0)")

print()
print("=" * 74)
print("三、TunnelTLS._pull 下行零字节与归因")
print("=" * 74)
t = P.TunnelTLS(FakeWS(b"\x00\x00" + TLS_HELLO), "proof.ovh.net", strict=True)
t._pull()
check(t.vless_hdr == "0000" and t._stripped, "正常首帧记录 VLESS 响应头证据")
check(t.downlink_bytes > 0, "正常首帧记录下行字节数")

t = P.TunnelTLS(FakeWS(b""), "proof.ovh.net", strict=True)
check(raises(t._pull, "downlink_zero"), "101 后连接关闭且零字节 -> downlink_zero")

t = P.TunnelTLS(FakeWS(socket.timeout("timed out")), "proof.ovh.net", strict=True)
check(raises(t._pull, "downlink_zero"), "101 后等不到任何帧 -> downlink_zero (带超时异常)")

t = P.TunnelTLS(FakeWS(b"\x09\x00" + TLS_HELLO), "proof.ovh.net", strict=True)
check(raises(t._pull, "vless_response"), "非法 version 在 _pull 阶段被拦")

# addons_len=5 但后续分片迟迟不来: _hdr_buf 长度一直够不着 need=7,
# 三次之后必须判 vless_response, 不能一直空转等下行。
t = P.TunnelTLS(FakeWS(b"\x00\x05", b"\x00\x05", b"\x00\x05"),
                 "proof.ovh.net", strict=True)
try:
    for _ in range(3):
        t._pull()
    stalled_ok = False
except P.ProbeError as e:
    stalled_ok = e.stage == "vless_response"
check(stalled_ok, "首帧分片连续 3 次不推进 -> vless_response, 不空转")

t = P.TunnelTLS(FakeWS(b"\x09\x00" + TLS_HELLO), "proof.ovh.net", strict=False)
try:
    t._pull()
    ok = t._stripped and not t.vless_hdr
except Exception:
    ok = False
check(ok, "非严格模式回归: 旧逻辑不校验 version, 行为保持不变")

print()
print("=" * 74)
print("四、probe_link 结构化结论 (不抛异常, 失败也带阶段)")
print("=" * 74)
KEYS = {"ok", "stage", "detail", "ws_ms", "tls_ms", "vless_hdr",
        "downlink_bytes", "status", "elapsed_ms"}
orig_ws, orig_tls = P.WS, P.TunnelTLS
FAKE_TLS_ERROR = [None]
FAKE_WS_OBJ = [None]


class FakeTunnelTLS:
    """替掉真实 TLS BIO: 这里只测 probe_link 的编排与字段填充, 不测 ssl 库本身。"""

    instances = []

    def __init__(self, ws, target, strict=False):
        self.ws = ws
        self.target = target
        self.strict = strict
        self.first_flight = b"CLIENTHELLO"
        self.vless_hdr = "0000"
        self.downlink_bytes = len(TLS_HELLO)
        self.handshakes = 0
        FakeTunnelTLS.instances.append(self)

    def handshake(self):
        self.handshakes += 1
        if FAKE_TLS_ERROR[0] is not None:
            raise FAKE_TLS_ERROR[0]


def fake_ws(*a, **kw):
    raise P.ProbeError("tls_edge", "模拟边缘 TLS 失败")


P.WS = fake_ws
try:
    r = P.probe_link(("1.2.3.4", 443), "/?ed=2048", "proof.ovh.net", timeout=1)
finally:
    P.WS = orig_ws
check(set(r) == KEYS, "返回字段齐全")
check(r["ok"] is False and r["stage"] == "tls_edge" and "模拟" in r["detail"],
      "失败也带准确阶段与原因, 不再是笼统的异常类名")
check(set(P.STAGES) == {"tcp", "tls_edge", "ws_upgrade", "vless_response",
                        "downlink_zero", "tls_inner"},
      "STAGES 覆盖六层: TCP / 边缘TLS / WS升级 / VLESS响应 / 零下行 / 隧道内TLS")


def run_fake_link(strict=True, error=None):
    """用内存假件跑一次 probe_link, 返回 (结论, 假 WS, 假 TLS)。"""
    ws_obj = FakeWS()
    FAKE_WS_OBJ[0] = ws_obj
    FAKE_TLS_ERROR[0] = error
    FakeTunnelTLS.instances.clear()
    P.WS = lambda *a, **kw: ws_obj
    P.TunnelTLS = FakeTunnelTLS
    try:
        r = P.probe_link(("1.2.3.4", 443), "/?ed=2048&proxyip=",
                         "proof.ovh.net", timeout=1, strict=strict)
    finally:
        P.WS, P.TunnelTLS = orig_ws, orig_tls
        FAKE_TLS_ERROR[0] = None
    return r, ws_obj, (FakeTunnelTLS.instances[0] if FakeTunnelTLS.instances else None)


# --- 成功路径 (原版缺这一条, 导致 ok=True 分支从未被断言覆盖) ---
ok_info, ok_ws, ok_tls = run_fake_link(strict=True)
check(ok_info["ok"] is True and ok_info["stage"] == "ok", "成功路径: ok=True / stage=ok")
check(ok_info["vless_hdr"] == "0000" and ok_info["downlink_bytes"] == len(TLS_HELLO),
      "成功路径: 回传 VLESS 响应头与下行字节数证据")
check(ok_info["status"].startswith("HTTP/1.1 101") and ok_info["detail"] == "",
      "成功路径: 记录 WS 状态行且不带失败原因")
check(all(isinstance(ok_info[k], int) and ok_info[k] >= 0
          for k in ("ws_ms", "tls_ms", "elapsed_ms")),
      "成功路径: 三个耗时字段均为非负整数")
check(ok_tls is not None and ok_tls.handshakes == 1 and ok_tls.strict is True,
      "成功路径: 以严格模式完成且只握手一次")
sent = ok_ws.sent[0] if ok_ws.sent else b""
vless_head = P.vless_header("proof.ovh.net", 443)
check(sent.startswith(vless_head) and sent.endswith(b"CLIENTHELLO")
      and len(sent) == len(vless_head) + len(b"CLIENTHELLO"),
      "成功路径: 首帧发送的是 VLESS 头 + ClientHello (合并发送)")
check(ok_ws.s.closed, "成功路径: finally 关闭 socket, 不泄漏连接")

# --- 失败阶段传播 ---
zero_info, _, _ = run_fake_link(error=P.ProbeError("downlink_zero", "101 后零下行"))
check(zero_info["ok"] is False and zero_info["stage"] == "downlink_zero"
      and "零下行" in zero_info["detail"],
      "downlink_zero 经 probe_link 原样保留, 不被吞成通用异常")
vless_info, _, _ = run_fake_link(error=P.ProbeError("vless_response", "version=9"))
check(vless_info["ok"] is False and vless_info["stage"] == "vless_response",
      "vless_response 经 probe_link 原样保留")
inner_info, _, _ = run_fake_link(error=P.ProbeError("tls_inner", "隧道内 TLS 失败"))
check(inner_info["ok"] is False and inner_info["stage"] == "tls_inner",
      "tls_inner 经 probe_link 原样保留, 六层归因不混淆")
plain_info, _, _ = run_fake_link(strict=False, error=RuntimeError("握手崩了"))
check(plain_info["ok"] is False and plain_info["stage"] == "vless_response"
      and "RuntimeError" in plain_info["detail"],
      "非严格模式的普通异常归到当前阶段, detail 带异常类名")

# --- 非严格模式成功回归: 旧调用方 (测速脚本) 不被改坏 ---
legacy_info, _, legacy_tls = run_fake_link(strict=False)
check(legacy_info["ok"] is True and legacy_tls is not None
      and legacy_tls.strict is False,
      "非严格模式回归: 成功链路行为不变, strict 正确下传")

print()
print("=" * 74)
print(f"结果: {len(PASS)} 通过 / {len(FAIL)} 失败")
if FAIL:
    for f in FAIL:
        print("  失败:", f)
    sys.exit(1)
print("全部通过")
