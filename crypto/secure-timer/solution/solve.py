#!/usr/bin/env python3
import json
import os
import time

from typing import Tuple
from telnetlib import Telnet

from Crypto.PublicKey import ECC
from Crypto.Util.number import bytes_to_long
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256


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


def readline(tn: Telnet):
    return tn.read_until(b"\n")


def json_recv(tn: Telnet):
    line = readline(tn)
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def current_time(tn: Telnet):
    request = {
        "command": "current_time",
    }
    json_send(tn, request)
    res = json_recv(tn)
    return res["res"], res["r"], res["s"]


def unpause_timer(tn: Telnet):
    request = {
        "command": "unpause",
    }
    json_send(tn, request)
    res = json_recv(tn)
    return res["res"], res["r"], res["s"]


def pause_timer(tn: Telnet):
    request = {
        "command": "pause",
    }
    json_send(tn, request)
    res = json_recv(tn)
    return res["res"], res["r"], res["s"]


def reduced_row_echelon_form_mod(matrix, mod):
    """
    Computes the reduced row echelon form of a matrix in modular arithmetic.

    Args:
        matrix: The matrix on which RREF will be performed (list of lists).
        mod: The modulus for modular arithmetic.

    Returns:
        The matrix after RREF in modular arithmetic (list of lists).
    """
    num_rows = len(matrix)
    num_cols = len(matrix[0])

    pivot = 0
    for col in range(num_cols):
        if pivot >= num_rows:
            break

        # Find the pivot row
        pivot_row = pivot
        while pivot_row < num_rows and matrix[pivot_row][col] == 0:
            pivot_row += 1

        if pivot_row == num_rows:
            continue

        # Swap pivot row with the current row
        matrix[pivot], matrix[pivot_row] = matrix[pivot_row], matrix[pivot]

        # Scale the pivot row to make the pivot element equal to 1
        pivot_elem = matrix[pivot][col]
        pivot_inv = pow(pivot_elem, -1, mod)
        matrix[pivot] = [(elem * pivot_inv) % mod for elem in matrix[pivot]]

        # Perform row operations to eliminate elements above and below the pivot
        for row in range(num_rows):
            if row != pivot:
                multiplier = matrix[row][col]
                matrix[row] = [
                    (elem - multiplier * matrix[pivot][c]) % mod
                    for c, elem in enumerate(matrix[row])
                ]

        pivot += 1

    return matrix


def generate_tmp(msg: bytes, q: int) -> int:
    """With hight probability this function returns the tmp value used to derive k"""

    def bits2octets(b: bytes, q_size: int) -> bytes:
        return (bytes_to_long(b) % q).to_bytes(q_size, "big")

    def bits2int(b: bytes, qlen: int) -> int:
        pre_b = bytes_to_long(b)
        if pre_b.bit_length() >= qlen:
            return pre_b >> (pre_b.bit_length() - qlen)
        else:
            return pre_b

    qlen = q.bit_length()
    q_size = (qlen + 7) // 8
    digest_size = SHA256.new().digest_size

    h1 = SHA256.new(msg).digest()

    h1_octets = bits2octets(h1, q_size)

    K = b"\x00" * digest_size
    V = b"\x01" * digest_size

    K = HMAC.new(K, V + b"\x00" + h1_octets, SHA256).digest()
    V = HMAC.new(K, V, SHA256).digest()

    K = HMAC.new(K, V + b"\x01" + h1_octets, SHA256).digest()
    V = HMAC.new(K, V, SHA256).digest()

    T = b""
    tlen = bytes_to_long(T).bit_length()
    while tlen < qlen:
        V = HMAC.new(K, V, SHA256).digest()
        T = T + V
        tlen = bytes_to_long(T).bit_length()
    return bits2int(T, qlen)


def attack(tn: Telnet):
    q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # curve order
    qlen = q.bit_length()  # size in bits
    q_size = (qlen + 7) // 8  # size in bytes

    signatures = []
    # collect enough signatures to construct a system of linear equations
    # that can be solved (unknowns are the bits of the secret key d)
    while len(signatures) < qlen:
        res, r, s = current_time(tn)
        tmp = generate_tmp(res.encode(), q)
        h = bytes_to_long(SHA256.new(res.encode()).digest()) % q
        signatures.append((r, s, tmp, h))

        res, r, s = pause_timer(tn)
        tmp = generate_tmp(res.encode(), q)
        h = bytes_to_long(SHA256.new(res.encode()).digest()) % q
        signatures.append((r, s, tmp, h))

        res, r, s = current_time(tn)
        tmp = generate_tmp(res.encode(), q)
        h = bytes_to_long(SHA256.new(res.encode()).digest()) % q
        signatures.append((r, s, tmp, h))

        res, r, s = unpause_timer(tn)
        tmp = generate_tmp(res.encode(), q)
        h = bytes_to_long(SHA256.new(res.encode()).digest()) % q
        signatures.append((r, s, tmp, h))
        time.sleep(1)

    # pause the timer to ensure that you do not exceed the deadline
    res, _, _ = pause_timer(tn)
    print(res)

    lsb_len = (q_size - (q_size // 2)) * 8  # size in bits
    msb_len = (q_size // 2) * 8  # size in bits

    msb_mask = ((2**msb_len) - 1) << lsb_len
    lsb_mask = (2**lsb_len) - 1

    equations = []
    for signature in signatures[:qlen]:
        equation = []
        # lsb bits of the key (xnor)
        r, s, tmp, h = signature[0], signature[1], signature[2], signature[3]

        lsb_const = 0
        for i in range(lsb_len):
            bit_mask = 2**i
            tmp_i = tmp & (bit_mask)
            bit_coefficient = r * bit_mask - s * bit_mask
            if tmp_i == 0:
                bit_coefficient += 2 * s * bit_mask
            else:
                lsb_const += 2 * s * bit_mask
            equation.append(bit_coefficient)

        for i in range(lsb_len, qlen):
            bit_mask = 2**i
            tmp_i = tmp & (bit_mask)
            bit_coefficient = r * bit_mask - s * bit_mask + 2 * s * tmp_i
            equation.append(bit_coefficient)

        k_const = tmp + lsb_mask
        equation.append(s * k_const - h - lsb_const)
        equations.append(equation)

    solution = reduced_row_echelon_form_mod(equations, q)

    d = 0
    for idx, row in enumerate(solution):
        d += row[-1] * (2**idx)

    flag_command = "flag"
    r, s = ECDSA().sign(
        ECC.EccKey(curve=ECDSA().curve_name, d=d), flag_command.encode()
    )

    request = {
        "command": flag_command,
        "r": r,
        "s": s,
    }
    json_send(tn, request)
    print(json_recv(tn))


if __name__ == "__main__":
    if "REMOTE" in os.environ:
        HOSTNAME = ""
    else:
        HOSTNAME = "localhost"
    PORT = 50002
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
