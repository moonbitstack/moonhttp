#!/usr/bin/env python3
"""A permessage-deflate client that talks to the echo endpoint in this repo.

This is the check that does not need Docker: it speaks RFC 6455 and RFC 7692 with
zlib, which is what every browser does, and asserts that what comes back is what a
browser would expect. Autobahn covers far more ground — scripts/autobahn/run.sh
runs it — but this is what can be run on any machine with Python.

    moon run src/examples/16-ws-echo &
    python3 scripts/autobahn/interop.py
"""

import base64
import hashlib
import os
import socket
import struct
import sys
import zlib

HOST, PORT = "127.0.0.1", 9001
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG, OP_CONT = 0x1, 0x2, 0x8, 0x9, 0xA, 0x0


class Client:
    """One connection, with the window kept across messages like a browser's."""

    def __init__(self, offer="permessage-deflate; client_max_window_bits=15"):
        self.sock = socket.create_connection((HOST, PORT), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            "GET / HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Extensions: {offer}\r\n"
            "\r\n"
        )
        self.sock.sendall(request.encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise AssertionError("the server closed during the handshake")
            self.buf += chunk
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        self.head = head.decode("latin-1")
        lines = self.head.split("\r\n")
        assert lines[0].startswith("HTTP/1.1 101"), self.head
        fields = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            fields[name.strip().lower()] = value.strip()
        want = base64.b64encode(
            hashlib.sha1((key + GUID).encode()).digest()
        ).decode()
        assert fields.get("sec-websocket-accept") == want, self.head
        self.extension = fields.get("sec-websocket-extensions", "")
        self.compressing = "permessage-deflate" in self.extension
        # One decompressor for the whole connection: the terms keep the window.
        self.inflate = zlib.decompressobj(-15)
        self.deflate = zlib.compressobj(6, zlib.DEFLATED, -15)

    # ---------------------------------------------------------------- framing

    def send(self, opcode, payload, fin=True, rsv1=False):
        mask = os.urandom(4)
        first = (0x80 if fin else 0) | (0x40 if rsv1 else 0) | opcode
        n = len(payload)
        if n <= 125:
            header = struct.pack("!BB", first, 0x80 | n)
        elif n <= 0xFFFF:
            header = struct.pack("!BBH", first, 0x80 | 126, n)
        else:
            header = struct.pack("!BBQ", first, 0x80 | 127, n)
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(header + mask + body)

    def compress(self, data):
        out = self.deflate.compress(data) + self.deflate.flush(zlib.Z_SYNC_FLUSH)
        assert out.endswith(b"\x00\x00\xff\xff")
        return out[:-4]

    def recv(self):
        while True:
            frame = self._frame()
            if frame is not None:
                return frame
            chunk = self.sock.recv(65536)
            if not chunk:
                raise AssertionError("the server closed without a frame")
            self.buf += chunk

    def _frame(self):
        if len(self.buf) < 2:
            return None
        b0, b1 = self.buf[0], self.buf[1]
        assert not (b1 & 0x80), "a server frame must not be masked"
        at, n = 2, b1 & 0x7F
        if n == 126:
            if len(self.buf) < 4:
                return None
            n = struct.unpack("!H", self.buf[2:4])[0]
            at = 4
        elif n == 127:
            if len(self.buf) < 10:
                return None
            n = struct.unpack("!Q", self.buf[2:10])[0]
            at = 10
        if len(self.buf) < at + n:
            return None
        payload, self.buf = self.buf[at : at + n], self.buf[at + n :]
        return (b0 & 0x80) != 0, b0 & 0x0F, (b0 & 0x40) != 0, payload

    def message(self, opcode, payload, compressed=None):
        """Send a message and read the echo, which may arrive in fragments."""
        compressed = self.compressing if compressed is None else compressed
        data = self.compress(payload) if compressed else payload
        self.send(opcode, data, rsv1=compressed)
        out, rsv1_seen = b"", False
        while True:
            fin, op, rsv1, part = self.recv()
            rsv1_seen = rsv1_seen or rsv1
            if op == OP_PING:
                continue
            out += part
            if fin:
                break
        # Whether the echo is compressed is the server's choice, so the answer is
        # read by the bit that came back rather than the one that went out.
        if rsv1_seen:
            return self.inflate.decompress(out + b"\x00\x00\xff\xff"), True
        return out, False

    def close_frame(self):
        while True:
            frame = self.recv()
            if frame[1] == OP_CLOSE:
                return struct.unpack("!H", frame[3][:2])[0] if len(frame[3]) >= 2 else 0
            if frame[0]:
                return None


def check(name, condition, detail=""):
    print(("ok   " if condition else "FAIL ") + name + ("  " + detail if detail and not condition else ""))
    if not condition:
        raise SystemExit(1)


def main():
    text = b"Hello, compressed world. " * 20
    binary = bytes((i * 37) & 0xFF for i in range(1000))

    client = Client()
    check("handshake and extension", client.compressing, client.extension)

    echo, rsv1 = client.message(OP_TEXT, text)
    check("compressed text round-trips", echo == text)
    check("the echo is compressed too", rsv1)

    echo, _ = client.message(OP_BINARY, binary)
    check("compressed binary round-trips", echo == binary)

    echo, _ = client.message(OP_TEXT, b"plain", compressed=False)
    check("an uncompressed message round-trips", echo == b"plain")

    # A message split inside the compressed stream: RSV1 on the first frame only.
    data = client.compress(text)
    client.send(OP_TEXT, data[: len(data) // 2], fin=False, rsv1=True)
    client.send(OP_CONT, data[len(data) // 2 :])
    out = b""
    while True:
        fin, op, _, part = client.recv()
        if op == OP_PING:
            continue
        out += part
        if fin:
            break
    check("a fragmented compressed message round-trips", client.inflate.decompress(out + b"\x00\x00\xff\xff") == text)

    # The window carries over: the second message is one long match against the first.
    client.message(OP_TEXT, text)
    echo, _ = client.message(OP_TEXT, text)
    check("the window carries over between messages", echo == text)

    client.send(OP_PING, b"ping")
    fin, op, _, payload = client.recv()
    check("a ping is answered", op == OP_PONG and payload == b"ping")

    # RSV1 on a continuation is §6.1's protocol error.
    client.send(OP_TEXT, b"", fin=False, rsv1=True)
    client.send(OP_CONT, b"\x00", rsv1=True)
    check("RSV1 on a continuation fails the connection with 1002", client.close_frame() == 1002)

    # A stream that does not decompress is 1007.
    other = Client()
    other.send(OP_TEXT, b"\xff\xff\xff\xff", rsv1=True)
    check("a stream that does not decompress fails with 1007", other.close_frame() == 1007)

    # And a plain close is echoed.
    third = Client()
    third.send(OP_CLOSE, struct.pack("!H", 1000))
    check("a close is echoed", third.close_frame() == 1000)

    print("all interop checks passed")


if __name__ == "__main__":
    sys.exit(main())
