#!/usr/bin/env python3
import json
import os

from telnetlib import Telnet

from Crypto.Cipher import AES


def readline(tn: Telnet):
    return tn.read_until(b"\n")


def json_recv(tn: Telnet):
    line = readline(tn)
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def xor(X: bytes, Y: bytes):
    return bytes(x ^ y for (x, y) in zip(X, Y))


def blockify(msg: bytes, block_size: int):
    block = [msg[i : i + block_size] for i in range(0, len(msg), block_size)]
    return block


def guest_login(tn: Telnet, username: bytes):
    request = {
        "command": "login",
        "login_type": "guest",
        "username": username.hex(),
    }
    json_send(tn, request)
    res = json_recv(tn)
    return res


def admin_login(tn: Telnet, token: bytes):
    request = {
        "command": "login",
        "login_type": "admin",
        "token": token.hex(),
    }
    json_send(tn, request)
    res = json_recv(tn)
    return res


def logout(tn: Telnet):
    request = {
        "command": "logout",
    }
    json_send(tn, request)
    res = json_recv(tn)
    return res


def add_pineapple(tn: Telnet):
    request = {
        "command": "select_toppings",
        "toppings_list": ["pineapple"],
    }
    json_send(tn, request)
    res = json_recv(tn)
    return res


def order_pizza(tn: Telnet):
    request = {
        "command": "order_pizza",
    }
    json_send(tn, request)
    res = json_recv(tn)
    return res


def attack(tn: Telnet):
    usefull_known_ptxt = b"min with token "
    known_ptxt_len = 112
    target_block_idx = (known_ptxt_len // 16) + 1

    admin_token = b""
    # recover admin's token byte by byte
    for i in range(15, -1, -1):
        # chosen boundary privilege to place the unknown plaintext byte
        # as the last byte of the target block
        current_known_ptxt = usefull_known_ptxt[15 - i :] + admin_token[: 15 - i]

        uname_boundaries = b"a" * i
        guest_login(tn, uname_boundaries)
        enc_report = add_pineapple(tn)["enc_report"]
        enc_report_blocks = blockify(bytes.fromhex(enc_report), AES.block_size)
        target_block = enc_report_blocks[target_block_idx]
        target_block_prev = enc_report_blocks[target_block_idx - 1]
        # last ciphertext block will be the next IV
        predictable_iv = enc_report_blocks[-1]
        logout(tn)

        for guess in range(256):
            guess_block = current_known_ptxt + guess.to_bytes(1, "big")
            # compute the first plaintext block necessary to enable detection of
            # the unknown last byte of the target block
            first_ptxt_block = xor(xor(guess_block, predictable_iv), target_block_prev)
            # the username can be the first plaintext block, you control it
            guest_login(tn, first_ptxt_block)
            enc_report = add_pineapple(tn)["enc_report"]
            enc_report_blocks = blockify(bytes.fromhex(enc_report), AES.block_size)
            resulted_block = enc_report_blocks[1]
            predictable_iv = enc_report_blocks[-1]
            logout(tn)

            if resulted_block == target_block:
                admin_token += guess.to_bytes(1, "big")
                break

    # use recovered admin's token to order a pineapple pizza to get the flag
    print(admin_login(tn, admin_token))
    print(add_pineapple(tn))
    print(order_pizza(tn))


if __name__ == "__main__":
    if "REMOTE" in os.environ:
        HOSTNAME = ""
    else:
        HOSTNAME = "localhost"
    PORT = 50001
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
