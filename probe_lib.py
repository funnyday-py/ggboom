#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在 edgetunnel 的 VLESS-over-WS 隧道上跑真正的 TLS, 用于测 HTTPS 下载速度。
对比两种出站模式:
  native : path=/            -> Worker 走默认反代池 (CF 出口)
  chain  : path=/video/<b64> -> Worker 走链式代理 (VPN Gate SSTP 中继)
"""
import base64
import os
import socket
import ssl
import struct
import sys
import time
import uuid as uuidlib

HOST = os.environ.get("EDT_DOMAIN", "vpn.cnzxmdd.cc.cd")
UUID_STR = os.environ.get("EDT_UUID", "f2afba09-d83b-43d1-b2df-f149941c4623")


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
    def __init__(self, path, entry=("www.postman.com", 443), timeout=25):
        self.s = socket.create_connection(entry, timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.s = ctx.wrap_socket(self.s, server_hostname=HOST)
        self.s.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((
            f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
        ).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = self.s.recv(4096)
            if not c:
                raise RuntimeError("握手期连接关闭")
            buf += c
        head, self.buf = buf.split(b"\r\n\r\n", 1)
        self.status = head.split(b"\r\n")[0].decode("latin-1")
        if "101" not in self.status:
            raise RuntimeError(f"WS 握手失败: {self.status}")

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

    def __init__(self, ws, target_host, early=True):
        self.ws = ws
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

    def _flush(self):
        d = self.out.read()
        if d:
            self.ws.send(d)

    def _pull(self):
        """拉一帧; 首帧要先剥掉 VLESS 响应头 (version + addonLen + addons)"""
        d = self.ws.recv()
        if not d:
            raise RuntimeError("隧道断开")
        if not self._stripped:
            self._hdr_buf += d
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
