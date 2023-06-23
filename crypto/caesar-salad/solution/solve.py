from itertools import cycle

message = b"\xcb\xcb\xdb\xcb\xf3\xf1\xb8\xfd\xd7\xeb\xe9\xe6\xd7\xe9\xe4\xff\xe9\xf1\xfb\xd7\xea\xfa\xfd\xfc\xed\xee\xe7\xfa\xeb\xbb\xd7\xe9\xd7\xfb\xe5\xe9\xe4\xe4\xd7\xe3\xbb\xf1\xd7\xfb\xf8\xbc\xeb\xed\xf5"


def xor(a, b):
    if len(a) < len(b):
        a, b = b, a
    return bytes([i ^ j for i, j in zip(a, cycle(b))])


for i in range(256):
    key = i.to_bytes(1, "big")
    candidate_flag = xor(message, key)
    if b"CCSC{" in candidate_flag:
        print(candidate_flag)
