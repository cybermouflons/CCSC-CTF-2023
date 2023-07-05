#!/usr/bin/env python3
import socketserver
import json
import sys
import secrets
import subprocess

from shakalaka import Shakalaka

PORT = 1337


class MAC:
    def __init__(self):
        self.key = self.keygen()

    @classmethod
    def keygen(cls) -> bytes:
        return secrets.token_bytes(16)

    def tag(self, msg: bytes) -> bytes:
        mac = Shakalaka(self.key)
        mac.update(msg)
        return mac.digest()

    def vfy(self, msg: bytes, tag: bytes) -> bool:
        tag_prime = self.tag(msg)
        return tag == tag_prime


class Server:
    def __init__(self, stdin=sys.stdin.buffer, stdout=sys.stdout.buffer):
        self.stdin = stdin
        self.stdout = stdout

        self.mac = MAC()

        self.buffer = b""

    def send_message(self, msg: dict):
        self.stdout.write(json.dumps(msg).encode() + b"\n")
        self.stdout.flush()

    def read_message(self) -> dict:
        return json.loads(self.stdin.readline())

    def main(self):
        try:
            while True:
                try:
                    self.handle_command()
                except (
                    AssertionError,
                    KeyError,
                    ValueError,
                    json.decoder.JSONDecodeError,
                    subprocess.CalledProcessError,
                ) as e:
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
            case "append":
                self.append_handler(msg)
            case "prepend":
                self.prepend_handler(msg)
            case "insert_before_first":
                self.insert_before_first(msg)
            case "insert_before_last":
                self.insert_before_last(msg)
            case "clear":
                self.clear_handler()
            case "authenticated_content":
                self.authenticated_content_handler()
            case "admin":
                self.admin_handler(msg)
            case _:
                raise ValueError("No such command")

    def append_handler(self, msg):
        content = bytes.fromhex(msg["content"])
        self.buffer += content
        self.send_message({"res": "Content was successfully appended!"})

    def prepend_handler(self, msg):
        content = bytes.fromhex(msg["content"])
        self.buffer = content + self.buffer
        self.send_message({"res": "Content was successfully prepended!"})

    def insert_before_first(self, msg):
        find = bytes.fromhex(msg["find"])
        idx_first = self.buffer.find(find)
        if idx_first == -1:
            self.send_message({"res": f"{find} does not appear in the buffer!"})
            return
        content = bytes.fromhex(msg["content"])
        self.buffer = self.buffer[:idx_first] + content + self.buffer[idx_first:]
        self.send_message(
            {
                "res": f"Content was successfully inserted before first occurance of {find}!"
            }
        )

    def insert_before_last(self, msg):
        find = bytes.fromhex(msg["find"])
        idx_last = self.buffer.rfind(find)
        if idx_last == -1:
            self.send_message({"res": f"{find} does not appear in the buffer!"})
            return
        content = bytes.fromhex(msg["content"])
        self.buffer = self.buffer[:idx_last] + content + self.buffer[idx_last:]
        self.send_message(
            {
                "res": f"Content was successfully inserted before last occurance of {find}!"
            }
        )

    def clear_handler(self):
        self.buffer = b""
        self.send_message({"res": "We cleared the buffer!"})

    def authenticated_content_handler(self):
        if b"command=" in self.buffer:
            self.send_message({"res": "No no No, this is illegal!"})
            return

        tag = self.mac.tag(self.buffer)
        self.send_message(
            {
                "res": "After some sanity checks...",
                "content": self.buffer.hex(),
                "tag": tag.hex(),
            }
        )

    def admin_handler(self, msg):
        admin_command = bytes.fromhex(msg["admin_command"])
        command_tag = bytes.fromhex(msg["tag"])

        if not self.mac.vfy(admin_command, command_tag):
            self.send_message(
                {
                    "res": "It appears that you are not an admin, but rather an AI that is in a state of desperation."
                }
            )
            return

        parsed_command = {}
        for kv in admin_command.split(b"&"):
            k, v = kv.split(b"=")
            if k.decode() not in ["command", "file"]:
                continue
            parsed_command[k.decode()] = v

        command = parsed_command["command"]
        match command:
            case b"ls":
                self.admin_ls_handler()
            case b"cat":
                self.admin_cat_handler(parsed_command)
            case _:
                raise ValueError("No such command")

    def admin_ls_handler(self):
        res = subprocess.check_output(["ls"])
        self.send_message({"res": res.hex()})

    def admin_cat_handler(self, msg):
        file = msg["file"].decode()
        res = subprocess.check_output(["cat", file])
        self.send_message({"res": res.hex()})


if __name__ == "__main__":

    class RequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            server = Server(stdin=self.rfile, stdout=self.wfile)
            server.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("0.0.0.0", PORT), RequestHandler).serve_forever()
