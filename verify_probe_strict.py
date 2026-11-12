#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""分层严格校验的本地单测: 用假 WS 帧复现四类「假活」, 并与旧口径对比。

不联网、不依赖真实 Worker, 全部用内存里的字节串跑, 因此可以随时回归。

覆盖:
  1. 伪 101 (Sec-WebSocket-Accept 不符 / 状态行蒙混)  —— 旧口径漏判
  2. WS 101 合法但下行零字节                        —— 旧口径靠超时兜底, 无归因
  3. VLESS 响应头 version 非法 / 剥完不是 TLS 记录     —— 旧口径漏判
  4. 正常链路 00 00 + TLS Handshake                  —— 新旧都应通过
  5. 非严格模式回归: 旧接口行为完全不变

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


class FakeWS:
    """只实现 _pull 需要的 recv/send, 帧可预置为字节或异常。"""

    def __init__(self, *frames):
        self.frames = list(frames)
        self.sent = []

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

bad = valid_head(key, accept="AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
_, _ = P.parse_ws_upgrade(bad, key, strict=False)          # 旧口径: 只看 "101" in status
check(True, "伪 101 (Accept 不符) 旧口径放过 —— 这是漏判基线")
check(raises(lambda: P.parse_ws_upgrade(bad, key, strict=True), "ws_upgrade"),
      "伪 101 被严格校验拦在 ws_upgrade")

no_upgrade = head.replace(b"Upgrade: websocket", b"X-Other: websocket")
check(raises(lambda: P.parse_ws_upgrade(no_upgrade, key, strict=True), "ws_upgrade"),
      "缺 Upgrade: websocket 被拦")

fake_status = b"HTTP/1.1 404 Not Found (ref 1013)\r\nUpgrade: websocket\r\n" \
              b"Connection: Upgrade\r\n" + f"Sec-WebSocket-Accept: {P.ws_accept(key)}\r\n".encode()
P.parse_ws_upgrade(fake_status, key, strict=False)          # 旧口径命中 "101" 子串
check(True, "状态行含 '101' 子串的 404 旧口径放过 —— 第二处漏判基线")
check(raises(lambda: P.parse_ws_upgrade(fake_status, key, strict=True), "ws_upgrade"),
      "非 101 状态行被严格校验拦住")

print()
print("=" * 74)
print("二、VLESS 响应头内容")
print("=" * 74)
need, rest, hdr = P.check_vless_response(b"\x00\x00" + TLS_HELLO)
check(hdr.hex() == "0000" and rest[:1] == b"\x16", "00 00 + TLS Handshake 通过")
need, rest, hdr = P.check_vless_response(b"\x00")
check(hdr == b"", "首帧分片只到 1 字节时等待补齐, 不误判")

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
orig_ws = P.WS


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

print()
print("=" * 74)
print(f"结果: {len(PASS)} 通过 / {len(FAIL)} 失败")
if FAIL:
    for f in FAIL:
        print("  失败:", f)
    sys.exit(1)
print("全部通过")
