from itertools import cycle

flag = b"CCSC{y0u_can_always_bruteforc3_a_small_k3y_sp4ce}"

key = b"\x88"


def xor(a, b):
    if len(a) < len(b):
        a, b = b, a
    return bytes([i ^ j for i, j in zip(a, cycle(b))])


ciphertext = xor(flag, key)
print(ciphertext)
