#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在 edgetunnel 的 VLESS-over-WS 隧道上跑真正的 TLS, 用于测 HTTPS 下载速度。
对比两种出站模式:
  native : path=/            -> Worker 走默认反代池 (CF 出口)
  chain  : path=/video/<b64> -> Worker 走链式代理 (VPN Gate SSTP 中继)
"""
import base64
import hashlib
import os
import socket
import ssl
import struct
import sys
import time
import uuid as uuidlib

HOST = os.environ.get("EDT_DOMAIN", "vpn.cnzxmdd.cc.cd")
UUID_STR = os.environ.get("EDT_UUID", "f2afba09-d83b-43d1-b2df-f149941c4623")

WS_ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# 链路分层: 失败时用它标记死在哪一段, 便于区分「入口挂了」和「目标站抖动」
STAGES = ("tcp", "tls_edge", "ws_upgrade", "vless_response", "downlink_zero", "tls_inner")


class ProbeError(RuntimeError):
    """链路探测失败, stage 标明失败阶段, detail 是具体原因。"""

    def __init__(self, stage, detail):
        self.stage = stage
        self.detail = detail
        super().__init__(f"[{stage}] {detail}")


def ws_accept(key):
    """RFC 6455 §4.2.2: Sec-WebSocket-Accept = base64(sha1(key + GUID))。"""
    return base64.b64encode(
        hashlib.sha1((key + WS_ACCEPT_GUID).encode("ascii")).digest()
    ).decode("ascii")


def parse_ws_upgrade(head_bytes, key, strict=False):
    """解析 WS 握手响应头。strict=True 时按 RFC 6455 逐项校验。

    返回 (status_line, headers_dict)。注意: 实测「死入口」同样返回完全合法的 101,
    所以这里的校验只证明「对面是个合规的 WebSocket 端点」, **不能当作可用性判据**;
    可用性由后续 VLESS 响应头 + 隧道内 TLS 下行决定。
    """
    lines = head_bytes.decode("latin-1", "replace").split("\r\n")
    status = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    if "101" not in status:
        raise RuntimeError(f"WS 握手失败: {status}")
    if not strict:
        return status, headers
    if not status.startswith("HTTP/1.") or " 101 " not in status:
        raise ProbeError("ws_upgrade", f"状态行不是标准 101: {status[:60]}")
    if headers.get("upgrade", "").lower() != "websocket":
        raise ProbeError("ws_upgrade", "缺 Upgrade: websocket")
    if "upgrade" not in headers.get("connection", "").lower():
        raise ProbeError("ws_upgrade", "缺 Connection: Upgrade")
    want, got = ws_accept(key), headers.get("sec-websocket-accept", "")
    if got != want:
        raise ProbeError("ws_upgrade", f"Sec-WebSocket-Accept 不匹配 (伪 101): got={got[:28]}")
    return status, headers


def check_vless_response(buf):
    """校验 VLESS 响应头内容, 返回 (需要总长度, 剥掉头后的数据, 头字节)。

    实测正常响应是 00 00 (version=0, addons_len=0) 紧接 TLS ServerHello (16 03 03...)。
    旧逻辑只按 addons_len 盲目剥离, 不校验 version, 也不管剥完剩下的是什么,
    因此「错误页 / 非协议数据」可能被当成合法隧道。
    """
    if len(buf) < 2:
        return 2, b"", b""
    ver, addon = buf[0], buf[1]
    need = 2 + addon
    # 这两项只要读满 2 字节就能判, 不必等 addons 补齐 (异常帧可能永远不补齐)
    if ver != 0:
        raise ProbeError("vless_response", f"version={ver} (应为 0), 疑似错误页或伪造响应")
    if addon > 64:
        raise ProbeError("vless_response", f"addons_len={addon} 异常偏大")
    if len(buf) < need:
        return need, b"", b""
    rest = buf[need:]
    hdr = buf[:need]
    if rest and rest[0] != 0x16:
        raise ProbeError("vless_response",
                         f"剥离响应头后首字节 0x{rest[0]:02x}, 不是 TLS Handshake 记录")
    return need, rest, hdr


# ---------------- WebSocket ----------------
def _frame(payload: bytes, opcode: int = 0x2) -> bytes:
    b = bytearray([0x80 | opcode])
    n = len(payload)
    if n < 126:
        b.append(0x80 | n)
    elif n < 65536:
        b.append(0x80 | 126)
        b += struct.pack(">H", n)
    else:
        b.append(0x80 | 127)
        b += struct.pack(">Q", n)
    mask = os.urandom(4)
    b += mask
    b += bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    return bytes(b)


class WS:
    def __init__(self, path, entry=("www.postman.com", 443), timeout=25, strict=False):
        self.strict = strict
        self.headers = {}
        self.key = base64.b64encode(os.urandom(16)).decode()
        try:
            self.s = socket.create_connection(entry, timeout=timeout)
        except Exception as e:
            if strict:
                raise ProbeError("tcp", f"{type(e).__name__}: {str(e)[:60]}") from e
            raise
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.s = ctx.wrap_socket(self.s, server_hostname=HOST)
        except Exception as e:
            if strict:
                raise ProbeError("tls_edge", f"{type(e).__name__}: {str(e)[:60]}") from e
            raise
        self.s.settimeout(timeout)
        key = self.key
        self.s.sendall((
            f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
        ).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            try:
                c = self.s.recv(4096)
            except Exception as e:
                if strict:
                    raise ProbeError("ws_upgrade",
                                     f"等待 WS 升级响应失败: {type(e).__name__}") from e
                raise
            if not c:
                if strict:
                    raise ProbeError("ws_upgrade", "握手期连接关闭, 未收到响应头")
                raise RuntimeError("握手期连接关闭")
            buf += c
        head, self.buf = buf.split(b"\r\n\r\n", 1)
        self.status, self.headers = parse_ws_upgrade(head, key, strict=strict)

    def send(self, data: bytes):
        self.s.sendall(_frame(data))

    def _take(self, n):
        while len(self.buf) < n:
            c = self.s.recv(262144)
            if not c:
                raise RuntimeError("连接关闭")
            self.buf += c
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self, maxn=262144):
        """返回隧道明文(二进制帧 payload), 无数据则返回 b'' """
        while True:
            if len(self.buf) < 2:
                c = self.s.recv(262144)
                if not c:
                    return b""
                self.buf += c
            op = self.buf[0] & 0x0F
            ln = self.buf[1] & 0x7F
            off = 2
            if ln == 126:
                if len(self.buf) < 4:
                    self.buf += self.s.recv(262144)
                    continue
                ln = struct.unpack(">H", self.buf[2:4])[0]
                off = 4
            elif ln == 127:
                if len(self.buf) < 10:
                    self.buf += self.s.recv(262144)
                    continue
                ln = struct.unpack(">Q", self.buf[2:10])[0]
                off = 10
            if len(self.buf) < off + ln:
                c = self.s.recv(262144)
                if not c:
                    return b""
                self.buf += c
                continue
            payload = self.buf[off:off + ln]
            self.buf = self.buf[off + ln:]
            if op == 0x8:
                return b""
            if op in (0x2, 0x0):
                if payload:
                    return payload
            # ping/pong 等忽略, 继续读


def vless_header(target_host, target_port):
    b = bytearray([0, *uuidlib.UUID(UUID_STR).bytes, 0, 1])
    b += struct.pack(">H", target_port)
    hb = target_host.encode()
    b.append(2)
    b.append(len(hb))
    b += hb
    return bytes(b)


# ---------------- TLS over tunnel ----------------
class TunnelTLS:
    """把 WS 隧道当成裸 TCP, 在上面跟目标站做 TLS
    第一帧必须把 VLESS 头与 ClientHello 合并发送, 才是真实客户端行为"""

    def __init__(self, ws, target_host, early=True, strict=False):
        self.ws = ws
        self.strict = strict
        self.inc = ssl.MemoryBIO()
        self.out = ssl.MemoryBIO()
        ctx = ssl.create_default_context()
        self.obj = ctx.wrap_bio(self.inc, self.out, server_hostname=target_host)
        self.first_flight = b""
        try:
            self.obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        except Exception:
            pass
        self.first_flight = self.out.read()   # ClientHello, 交给调用方与 VLESS 头合并
        self._hdr_buf = b""
        self._stripped = False
        # 严格模式下记录证据, 供探针写进健康数据
        self.vless_hdr = ""
        self.downlink_bytes = 0
        self._stalled = 0

    def _flush(self):
        d = self.out.read()
        if d:
            self.ws.send(d)

    def _pull(self):
        """拉一帧; 首帧要先剥掉 VLESS 响应头 (version + addonLen + addons)"""
        try:
            d = self.ws.recv()
        except Exception as e:
            if self.strict and not self._stripped:
                raise ProbeError("downlink_zero",
                                 f"WS 101 已建立但无下行帧: {type(e).__name__}") from e
            raise
        if not d:
            if self.strict and not self._stripped:
                raise ProbeError("downlink_zero", "WS 101 已建立但连接关闭, 下行零字节")
            raise RuntimeError("隧道断开")
        if self.strict:
            self.downlink_bytes += len(d)
        if not self._stripped:
            self._hdr_buf += d
            if self.strict:
                need, d, hdr = check_vless_response(self._hdr_buf)
                if not hdr:
                    self._stalled += 1
                    if self._stalled >= 3:
                        raise ProbeError("vless_response", "首帧分片不完整或不推进")
                    return
                self.vless_hdr = hdr.hex()
                self._hdr_buf = b""
                self._stripped = True
                self._stalled = 0
                if not d:
                    return
            else:
                if len(self._hdr_buf) < 2:
                    return
                need = 2 + self._hdr_buf[1]
                if len(self._hdr_buf) < need:
                    return
                d = self._hdr_buf[need:]
                self._stripped = True
                if not d:
                    return
        self.inc.write(d)

    def handshake(self):
        for _ in range(60):
            try:
                self.obj.do_handshake()
                self._flush()
                return
            except ssl.SSLWantReadError:
                self._flush()
                self._pull()
            except Exception as e:
                if self.strict:
                    raise ProbeError("tls_inner",
                                     f"{type(e).__name__}: {str(e)[:60]}") from e
                raise
        raise RuntimeError("TLS 握手未完成")

    def send(self, data):
        self.obj.write(data)
        self._flush()

    def recv(self, n=262144):
        for _ in range(80):
            try:
                return self.obj.read(n)
            except ssl.SSLWantReadError:
                self._pull()
            except ssl.SSLZeroReturnError:
                return b""
        return b""


def probe_link(entry, path, target, timeout=8, strict=True):
    """一次严格链路探测, 返回结构化结论 (不抛异常)。

    分层: tcp -> tls_edge -> ws_upgrade -> vless_response / downlink_zero -> tls_inner
    实测依据 (2026-11-12): 连判死的入口都会返回完全合法的 101 + Sec-WebSocket-Accept,
    所以 101 只证明「对面是合规 WS 端点」, 判活必须靠 VLESS 响应头内容 + 隧道内 TLS 下行。
    """
    t0 = time.time()
    ws = None
    tls = None
    stage = "tcp"
    info = {
        "ok": False, "stage": "", "detail": "", "ws_ms": 0, "tls_ms": 0,
        "vless_hdr": "", "downlink_bytes": 0, "status": "",
    }
    try:
        ws = WS(path, entry=entry, timeout=timeout, strict=strict)
        stage = "ws_upgrade"
        info["status"] = ws.status.strip()
        info["ws_ms"] = round((time.time() - t0) * 1000)
        tls = TunnelTLS(ws, target, strict=strict)
        stage = "vless_response"
        ws.send(vless_header(target, 443) + tls.first_flight)
        tls.handshake()
        stage = "tls_inner"
        info.update({
            "ok": True, "stage": "ok",
            "tls_ms": round((time.time() - t0) * 1000),
            "vless_hdr": tls.vless_hdr,
            "downlink_bytes": tls.downlink_bytes,
        })
    except ProbeError as e:
        info["stage"] = e.stage
        info["detail"] = e.detail
    except Exception as e:
        info["stage"] = stage
        info["detail"] = f"{type(e).__name__}: {str(e)[:70]}"
    finally:
        if tls:
            info["vless_hdr"] = info["vless_hdr"] or tls.vless_hdr
            info["downlink_bytes"] = info["downlink_bytes"] or tls.downlink_bytes
        try:
            if ws and getattr(ws, "s", None):
                ws.s.close()
        except Exception:
            pass
    info["elapsed_ms"] = round((time.time() - t0) * 1000)
    return info


def run(mode, chain_b64, target, url_path, entry, limit=30, want=None, ed=True):
    path = "/video/" + chain_b64 if mode == "chain" else "/"
    if ed:
        path += "?ed=2048"
    t0 = time.time()
    ws = WS(path, entry=entry)
    hs = (time.time() - t0) * 1000
    tls = TunnelTLS(ws, target[0])
    ws.send(vless_header(*target) + tls.first_flight)   # 头 + ClientHello 同帧
    tls.handshake()
    tlsh = (time.time() - t0) * 1000
    tls.send((f"GET {url_path} HTTP/1.1\r\nHost: {target[0]}\r\n"
              "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
              "Accept: */*\r\nConnection: close\r\n\r\n").encode())
    t1 = time.time()
    buf = b""
    body = b""
    ttfb = None
    while time.time() - t1 < limit:
        try:
            d = tls.recv()
        except Exception as e:
            print(f"    读取中断 {type(e).__name__}", flush=True)
            break
        if not d:
            break
        if not body:
            buf += d
            if b"\r\n\r\n" in buf:
                hdr, body = buf.split(b"\r\n\r\n", 1)
                ttfb = (time.time() - t1) * 1000
                print(f"    {hdr.split(chr(13).encode())[0].decode('latin-1','replace').strip()}", flush=True)
        else:
            body += d
        if want and len(body) >= want:
            break
    dt = time.time() - t1
    mbps = (len(body) * 8 / 1e6) / dt if dt > 0 else 0
    print(f"    WS {hs:.0f}ms / TLS {tlsh:.0f}ms / TTFB {ttfb if ttfb else -1:.0f}ms"
          f" | {len(body)/1024:.0f}KB in {dt:.1f}s = {mbps:.2f} Mbps", flush=True)
    return mbps, len(body)


if __name__ == "__main__":
    entry_host = os.environ.get("ENTRY", "www.postman.com:443").rsplit(":", 1)
    entry = (entry_host[0], int(entry_host[1]))
    b64 = sys.argv[1] if len(sys.argv) > 1 else None
    print(f"入口 {entry[0]}:{entry[1]}  目标 https://speed.cloudflare.com/__down?bytes=1048576", flush=True)
    print("--- native (CF 出口) ---", flush=True)
    try:
        run("native", None, ("speed.cloudflare.com", 443), "/__down?bytes=1048576", entry,
            limit=40, want=1048576)
    except Exception as e:
        print(f"    失败 {type(e).__name__}: {e}", flush=True)
