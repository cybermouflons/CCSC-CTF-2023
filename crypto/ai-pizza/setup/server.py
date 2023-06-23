#!/usr/bin/env python3
import socketserver
import json
import sys

from secret import FLAG, KEY

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

PORT = 50001


class Server:
    def __init__(self, flag, key, stdin=sys.stdin.buffer, stdout=sys.stdout.buffer):
        self.stdin = stdin
        self.stdout = stdout

        self.flag = flag

        cbc_key = HKDF(
            master=key,
            salt=None,
            key_len=16,
            hashmod=SHA256,
            context=b"cbc-encryption",
        )

        self.admin_token = HKDF(
            master=key,
            salt=None,
            key_len=16,
            hashmod=SHA256,
            context=b"admin-token",
        )

        self.cipher = AES.new(cbc_key, AES.MODE_CBC)

        self.current_user = None
        self.available_toppings = [
            "halloumi",
            "pineapple",
            "salami",
            "pepperoni",
            "mushroom",
        ]

        self.current_toppings = ["cheese"]

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
            case "login":
                self.login_handler(msg)
            case "logout":
                self.logout_handler()
            case "select_toppings":
                self.select_toppings_handler(msg)
            case "order_pizza":
                self.order_pizza_handler()
            case _:
                raise ValueError("No such command")

    def login_handler(self, msg):
        if self.current_user is not None:
            self.send_message({"res": "Logout first."})
            return

        login_type = msg["login_type"]

        if login_type == "admin":
            token = bytes.fromhex(msg["token"])
            if token == self.admin_token:
                self.current_user = b"admin"
            else:
                self.send_message({"res": "Invalid token!"})
                return
        elif login_type == "guest":
            username = bytes.fromhex(msg["username"])
            if username == b"admin":
                self.send_message(
                    {"res": "You didn't think that it would be that easy, right?"}
                )
                return
            self.current_user = username
        else:
            self.send_message({"res": "Unknown login type"})
            return

        self.send_message(
            {
                "res": f"Welcome {self.current_user.decode(errors='replace')}, order your custom pizza!"
            }
        )

    def logout_handler(self):
        if self.current_user is None:
            self.send_message({"res": "Already logged out."})
        else:
            self.current_user = None
            self.current_toppings = ["cheese"]
            self.send_message({"res": "Succesfully logged out."})

    def select_toppings_handler(self, msg):
        if self.current_user is None:
            self.send_message({"res": "Please login first."})
            return

        self.current_toppings = ["cheese"]
        toppings = msg["toppings_list"]
        for topping in toppings:
            if topping not in self.available_toppings:
                continue

            if topping == "pineapple" and self.current_user != b"admin":
                report = (
                    self.current_user
                    + b" loves pineapples... pineapples are forbidden for non admin users... "
                    + b"report this action to the admin with token "
                    + self.admin_token
                )
                enc_report = self.cipher.encrypt(pad(report, AES.block_size))
                self.send_message(
                    {
                        "res": "Send this encrypted report to the admin",
                        "enc_report": (self.cipher.iv + enc_report).hex(),
                    }
                )
                self.current_toppings = ["cheese"]
                return

            self.current_toppings.append(topping)

        self.send_message(
            {
                "res": f"Next step: Place an order for your {', '.join(self.current_toppings)} pizza."
            }
        )

    def order_pizza_handler(self):
        if self.current_user is None:
            self.send_message({"res": "Please login first."})
            return

        if "pineapple" in self.current_toppings:
            self.send_message(
                {
                    "res": f"Life is too short to eat bad pizza... so grab a flag: {self.flag}"
                }
            )
        else:
            self.send_message(
                {"res": f"Enjoy your {', '.join(self.current_toppings)} pizza"}
            )

        self.current_toppings = ["cheese"]


if __name__ == "__main__":

    class RequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            server = Server(flag=FLAG, key=KEY, stdin=self.rfile, stdout=self.wfile)
            server.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("0.0.0.0", PORT), RequestHandler).serve_forever()
