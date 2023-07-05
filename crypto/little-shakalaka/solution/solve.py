#!/usr/bin/env python3
import json
import os

from typing import Tuple
from telnetlib import Telnet

from shakalaka import Shakalaka


def readline(tn: Telnet):
    return tn.read_until(b"\n")


def json_recv(tn: Telnet):
    line = readline(tn)
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def append_content(tn: Telnet, content: bytes) -> dict:
    request = {
        "command": "append",
        "content": content.hex(),
    }
    json_send(tn, request)
    return json_recv(tn)


def authenticated_content(tn: Telnet) -> Tuple[bytes, bytes]:
    request = {
        "command": "authenticated_content",
    }
    json_send(tn, request)
    res = json_recv(tn)
    return bytes.fromhex(res["content"]), bytes.fromhex(res["tag"])


def clear_content(tn: Telnet) -> dict:
    request = {
        "command": "clear",
    }
    json_send(tn, request)
    return json_recv(tn)


def admin_command(tn: Telnet, command: bytes, tag: bytes) -> dict:
    request = {
        "command": "admin",
        "admin_command": command.hex(),
        "tag": tag.hex(),
    }
    json_send(tn, request)
    return json_recv(tn)


def attack(tn: Telnet):
    KEY_LEN = 16 * 8
    # we need to somehow discard the padding
    append_content(tn, b"file=")

    # the tag we get is truncated, we have to bruteforce
    # but remote is slow, you have to do the work locally otherwise no flag for you
    content1, tag1 = authenticated_content(tn)

    padded_content1 = Shakalaka.known_padded_message(content1, KEY_LEN)

    clear_content(tn)

    append_content(tn, padded_content1)

    # if we match this tag it means that we found the missing bytes
    _, target_tag = authenticated_content(tn)

    init_state = [int.from_bytes(tag1[t * 4 : (t + 1) * 4], "big") for t in range(7)]
    last_incomplete = (tag1[-2] << 29) + (tag1[-1] << 21)

    # find the missing bytes
    starting_L = len(padded_content1) * 8 + KEY_LEN
    for guess in range(2**21):
        guess_complete = last_incomplete + guess

        guess_tag = Shakalaka(H=init_state + [guess_complete], L=starting_L).digest()
        if guess_tag == target_tag:
            init_state.append(guess_complete)
            break

    ls_extension = b"&command=ls"
    ls_forged_tag = Shakalaka(M=ls_extension, H=init_state, L=starting_L).digest()
    ls_admin_command = padded_content1 + ls_extension

    ls_res = bytes.fromhex(admin_command(tn, ls_admin_command, ls_forged_tag)["res"])
    files = ls_res.split(b"\n")

    for file in files:
        cat_extension = b"&command=cat&file=" + file
        cat_forged_tag = Shakalaka(M=cat_extension, H=init_state, L=starting_L).digest()
        cat_admin_command = padded_content1 + cat_extension

        cat_res = admin_command(tn, cat_admin_command, cat_forged_tag)
        cand_flag = bytes.fromhex(cat_res["res"] if "res" in cat_res else "")
        if b"CCSC{" in cand_flag:
            print(cand_flag)
            break


if __name__ == "__main__":
    if "REMOTE" in os.environ:
        HOSTNAME = ""
    else:
        HOSTNAME = "localhost"
    PORT = 1337
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
