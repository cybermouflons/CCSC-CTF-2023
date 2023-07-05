from typing import List, Tuple


class Shakalaka:
    def __init__(self, M: bytes = b""):
        self.H = [
            0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
            0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
        ]
        self.K = [
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
            0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
            0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
            0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
            0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
            0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
            0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
            0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
            0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
        ]
        self.L = 0

        self._buffer = b""
        self.block_size = 64

        self.update(M)

    def blockify(self, msg: bytes) -> Tuple[List[bytes], bytes]:
        size = self.block_size
        if -(len(msg) % size) == 0:
            remaining = b""
        else:
            remaining = msg[-(len(msg) % size) :]
        return [msg[i : i + size] for i in range(0, len(msg) - 63, size)], remaining

    def _processing(self, block: bytes):
        assert len(block) == self.block_size

        ROTR = (
            lambda x, n: ((x >> (n & 0x1F)) | (x << (0x20 - (n & 0x1F)))) & 0xFFFFFFFF
        )
        CH = lambda x, y, z: (((x & y) ^ ((~x) & z))) & 0xFFFFFFFF
        MAJ = lambda x, y, z: ((x & y) ^ (x & z) ^ (y & z)) & 0xFFFFFFFF
        SHR = lambda x, n: (x & 0xFFFFFFFF) >> (n & 0x1F)
        BSIG0 = lambda x: (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
        BSIG1 = lambda x: (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
        SSIG0 = lambda x: (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
        SSIG1 = lambda x: (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

        W = []

        for t in range(0, 16):
            W.append(
                (block[4 * t] << 24)
                + (block[4 * t + 1] << 16)
                + (block[4 * t + 2] << 8)
                + block[4 * t + 3]
            )

        for t in range(16, 64):
            W.append(
                (SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16]) & 0xFFFFFFFF
            )

        a = self.H[0]
        b = self.H[1]
        c = self.H[2]
        d = self.H[3]
        e = self.H[4]
        f = self.H[5]
        g = self.H[6]
        h = self.H[7]

        for t in range(0, 64):
            T1 = (h + BSIG1(e) + CH(e, f, g) + self.K[t] + W[t]) & 0xFFFFFFFF
            T2 = (BSIG0(a) + MAJ(a, b, c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF

        self.H[0] = (self.H[0] + a) & 0xFFFFFFFF
        self.H[1] = (self.H[1] + b) & 0xFFFFFFFF
        self.H[2] = (self.H[2] + c) & 0xFFFFFFFF
        self.H[3] = (self.H[3] + d) & 0xFFFFFFFF
        self.H[4] = (self.H[4] + e) & 0xFFFFFFFF
        self.H[5] = (self.H[5] + f) & 0xFFFFFFFF
        self.H[6] = (self.H[6] + g) & 0xFFFFFFFF
        self.H[7] = (self.H[7] + h) & 0xFFFFFFFF

    def update(self, M: bytes):
        blocks, self._buffer = self.blockify(self._buffer + M)
        self.L += (len(blocks) * self.block_size) << 3

        for block in blocks:
            self._processing(block)

    def digest(self) -> bytes:
        SHR = lambda x, n: (x & 0xFFFFFFFF) >> (n & 0x1F)

        M_len = self.L + (len(self._buffer) << 3)
        assert M_len < (2**64)
        K = ((-(M_len + 8 - 0x01C0)) & 0x01FF) // 8
        blocks, _ = self.blockify(
            self._buffer + b"\x80" + b"\x00" * K + M_len.to_bytes(8, "little")
        )
        H_p = self.H.copy()
        for block in blocks:
            self._processing(block)
        H = self.H
        self.H = H_p

        digest = b""
        for t in range(7):
            digest += H[t].to_bytes(4, "big")
        digest += SHR(H[7], 21).to_bytes(2, "big")

        return digest

    def hexdigest(self) -> str:
        return self.digest().hex()
