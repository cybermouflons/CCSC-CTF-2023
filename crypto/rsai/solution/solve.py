#!/usr/bin/env python3
import json
import os

from typing import Tuple
from telnetlib import Telnet

from Crypto.Util.number import long_to_bytes, getPrime, GCD


def readline(tn: Telnet):
    return tn.read_until(b"\n")


def json_recv(tn: Telnet):
    line = readline(tn)
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def encrypted_flag(tn: Telnet) -> int:
    request = {
        "command": "encrypted_flag",
    }
    json_send(tn, request)
    res = json_recv(tn)["res"]
    ctxt = int(res.split("... ")[-1])
    return ctxt


def select_e(tn: Telnet, e: int):
    request = {
        "command": "select_e",
        "e": e,
    }
    json_send(tn, request)
    res = json_recv(tn)
    return res["e"], res["N"]


# source: https://www.geeksforgeeks.org/python-program-for-basic-and-extended-euclidean-algorithms-2/
def gcdExtended(a: int, b: int) -> Tuple[int, int, int]:
    """Function for extended Euclidean Algorithm

    Computes x, y and gcd such that:
    a*x + b*y = gcd
    where,
    gcd is the greatest common factor of a and b
    """
    # Base Case
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = gcdExtended(b % a, a)

    # Update x and y using results of recursive
    # call
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y


def edge_case(e: int, c: int, N: int):
    p = GCD(c, N)
    q = N // p
    phiN = (p - 1) * (q - 1)
    d = pow(e, -1, phiN)
    m = pow(c, d, N)
    flag = long_to_bytes(m)
    print(flag)


def attack(tn: Telnet):
    e1 = getPrime(17)
    e2 = getPrime(17)
    while e1 == e2:
        e2 = getPrime(17)

    e1, N = select_e(tn, e1)
    c1 = encrypted_flag(tn)

    e2, N = select_e(tn, e2)
    c2 = encrypted_flag(tn)

    # we check the edge cases because we need to compute the mod inverse of c1 or c2 mod N
    # but we are lucky in the edge cases because factorization is trivial
    if GCD(c1, N) != 1:
        edge_case(e1, c1, N)
        return

    if GCD(c2, N) != 1:
        edge_case(e2, c2, N)
        return

    gcd, x, y = gcdExtended(e1, e2)
    print(f"{N=}")
    print(f"{e1=}, {e2=}, {x=}, {y=}, {gcd=}")
    m = ((pow(c1, x, N)) * pow(c2, y, N)) % N

    flag = long_to_bytes(m)
    print(flag)


if __name__ == "__main__":
    if "REMOTE" in os.environ:
        HOSTNAME = ""
    else:
        HOSTNAME = "localhost"
    PORT = 50003
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
