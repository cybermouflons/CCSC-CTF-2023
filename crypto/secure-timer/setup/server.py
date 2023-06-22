#!/usr/bin/env python3
import socketserver
import json
import sys
import time

from typing import Tuple

from secret import FLAG

from Crypto.PublicKey import ECC
from Crypto.Util.number import bytes_to_long
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

PORT = 50002


def xor(X: bytes, Y: bytes):
    return bytes(x ^ y for (x, y) in zip(X, Y))


def xnor(X: bytes, Y: bytes):
    return bytes(~(x ^ y) & 0xFF for (x, y) in zip(X, Y))


class ECDSA:
    def __init__(self):
        self.curve_name = "P-256"
        self.q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # curve order
        self.G = ECC.EccPoint(
            x=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            y=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
            curve="P-256",
        )  # curve generator

    def keygen(self) -> ECC.EccKey:
        return ECC.generate(curve=self.curve_name)

    def generate_k(
        self, key: ECC.EccKey, msg: bytes, K_V: Tuple[bytes, bytes] = None
    ) -> int:
        def int2octets(x: int, q_size: int) -> bytes:
            return x.to_bytes(q_size, "big")

        def bits2octets(b: bytes, q_size: int) -> bytes:
            return (bytes_to_long(b) % self.q).to_bytes(q_size, "big")

        def bits2int(b: bytes, qlen: int) -> int:
            pre_b = bytes_to_long(b)
            if pre_b.bit_length() >= qlen:
                return pre_b >> (pre_b.bit_length() - qlen)
            else:
                return pre_b

        qlen = self.q.bit_length()
        q_size = (qlen + 7) // 8
        digest_size = SHA256.new().digest_size
        x_octets = int2octets(int(key.d), q_size)

        if K_V is None:
            h1 = SHA256.new(msg).digest()

            h1_octets = bits2octets(h1, q_size)

            K = b"\x00" * digest_size
            V = b"\x01" * digest_size

            K = HMAC.new(K, V + b"\x00" + h1_octets, SHA256).digest()
            V = HMAC.new(K, V, SHA256).digest()

            K = HMAC.new(K, V + b"\x01" + h1_octets, SHA256).digest()
            V = HMAC.new(K, V, SHA256).digest()
        else:
            # when r value is 0
            K, V = K_V

            K = HMAC.new(K, V + b"\x00", SHA256).digest()
            V = HMAC.new(K, V, SHA256).digest()

        while True:
            T = b""
            tlen = bytes_to_long(T).bit_length()
            while tlen < qlen:
                V = HMAC.new(K, V, SHA256).digest()
                T = T + V
                tlen = bytes_to_long(T).bit_length()
            tmp = bits2int(T, qlen).to_bytes(q_size, "big")
            k_bytes = xor(tmp[: q_size // 2], x_octets[: q_size // 2])
            k_bytes += xnor(tmp[q_size // 2 :], x_octets[q_size // 2 :])
            k = bytes_to_long(k_bytes)

            if 1 <= k <= self.q - 1:
                break

            K = HMAC.new(K, V + b"\x00", SHA256).digest()
            V = HMAC.new(K, V, SHA256).digest()

        return k, K, V

    def sign(self, key: ECC.EccKey, msg: bytes) -> Tuple[int, int]:
        h = bytes_to_long(SHA256.new(msg).digest()) % self.q

        K_V = None
        while True:
            k, K, V = self.generate_k(key, msg, K_V)
            K_V = (K, V)
            r = int((k * self.G).x) % self.q
            s = pow(k, -1, self.q) * (h + int(key.d) * r) % self.q

            if r != 0 and s != 0:
                break
        return r, s

    def verify(self, pub_key: ECC.EccPoint, msg: bytes, r: int, s: int) -> bool:
        if not (1 <= r <= self.q - 1 and 1 <= s <= self.q - 1):
            return False

        w = pow(s, -1, self.q)
        h = bytes_to_long(SHA256.new(msg).digest()) % self.q
        u1 = w * h % self.q
        u2 = w * r % self.q
        Z = u1 * self.G + u2 * pub_key

        return (int(Z.x) % self.q) == r


class Server:
    def __init__(self, flag, stdin=sys.stdin.buffer, stdout=sys.stdout.buffer):
        self.stdin = stdin
        self.stdout = stdout

        self.flag = flag

        self.priv_key = ECDSA().keygen()

        self.unpause_time = None
        self.prev_time = 0

    def send_message(self, msg: dict):
        self.stdout.write(json.dumps(msg).encode() + b"\n")
        self.stdout.flush()

    def read_message(self) -> dict:
        return json.loads(self.stdin.readline())

    def main(self):
        self.unpause_time = int(time.time())
        try:
            while True:
                try:
                    self.handle_command()
                except (KeyError, ValueError, json.decoder.JSONDecodeError) as e:
                    self.send_message(
                        {
                            "error": f"Failed to execute command: {type(e).__name__}: {str(e)}"
                        }
                    )
        except BrokenPipeError:
            pass

    def handle_command(self):
        msg = self.read_message()
        command = msg["command"]

        match command:
            case "unpause":
                self.timer_unpause_handler()
            case "pause":
                self.timer_pause_handler()
            case "current_time":
                self.timer_current_time_handler()
            case "flag":
                self.flag_handler(msg)
            case "public_key":
                self.public_key_handler()
            case _:
                raise ValueError("No such command")

    def timer_unpause_handler(self):
        if self.unpause_time is not None:
            self.send_message({"res": "You cannot unpause an already running timer"})
            return

        self.unpause_time = int(time.time())

        response = f"Timer unpaused at {self.prev_time}s"
        r, s = ECDSA().sign(self.priv_key, response.encode())
        self.send_message({"res": response, "r": r, "s": s})

    def timer_pause_handler(self):
        if self.unpause_time is None:
            self.send_message({"res": "You cannot pause a frozen timer"})
            return

        self.prev_time += int(time.time()) - self.unpause_time
        self.unpause_time = None

        response = f"Timer paused at {self.prev_time}s"
        r, s = ECDSA().sign(self.priv_key, response.encode())
        self.send_message({"res": response, "r": r, "s": s})

    def timer_current_time_handler(self):
        suffix = "[paused]" if self.unpause_time is None else ""
        response = f"Current time: {self.current_time()}s" + suffix
        r, s = ECDSA().sign(self.priv_key, response.encode())
        self.send_message({"res": response, "r": r, "s": s})

    def current_time(self) -> int:
        current_time = self.prev_time
        if self.unpause_time is not None:
            current_time += int(time.time()) - self.unpause_time
        return current_time

    def flag_handler(self, msg):
        deadline = 128
        if self.current_time() > deadline:
            self.send_message(
                {
                    "res": f"You are not allowed to issue this command when the timer exceeds {deadline}s... Restart the timer"
                }
            )
            return

        flag_sign = (int(msg["r"]), int(msg["s"]))
        flag_command = msg["command"]

        verified = ECDSA().verify(
            self.priv_key.public_key().pointQ, flag_command.encode(), *flag_sign
        )

        if verified:
            self.send_message(
                {
                    "res": f"I am so confident about my AI-generated deterministic ECDSA implementation, here is the flag: {self.flag}"
                }
            )
        else:
            self.send_message({"res": "Verification failed... tik tok tik tok"})

    def public_key_handler(self):
        """You can use this public key to verify the signatures in the timer responses"""
        Q = self.priv_key.public_key().pointQ
        self.send_message(
            {"res": "Server's Public Key coordinates", "x": int(Q.x), "y": int(Q.y)}
        )


if __name__ == "__main__":

    class RequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            server = Server(flag=FLAG, stdin=self.rfile, stdout=self.wfile)
            server.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("0.0.0.0", PORT), RequestHandler).serve_forever()
