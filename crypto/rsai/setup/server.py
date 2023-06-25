#!/usr/bin/env python3
import socketserver
import json
import sys

from secret import FLAG, PRIME_1, PRIME_2

from Crypto.Util.number import getPrime, GCD

PORT = 50003


class Server:
    def __init__(
        self, flag, prime_1, prime_2, stdin=sys.stdin.buffer, stdout=sys.stdout.buffer
    ):
        self.stdin = stdin
        self.stdout = stdout

        self.flag = int.from_bytes(flag.encode(), "big")

        # both primes are 1024 bits long and do not change over runs
        self.p = prime_1  # getPrime(1024)
        self.q = prime_2  # getPrime(1024)
        self.N = self.p * self.q

        self.phiN = (self.p - 1) * (self.q - 1)

        self.e = None
        self.d = None

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
            case "encrypted_flag":
                self.encrypted_flag_handler()
            case "select_e":
                self.select_e_handler(msg)
            case "decrypt":
                self.decrypt_handler(msg)
            case _:
                raise ValueError("No such command")

    def encrypted_flag_handler(self):
        if self.e is None:
            self.send_message({"res": "You have the freedom to choose e!"})
            return

        ctxt = pow(self.flag, self.e, self.N)
        self.send_message({"res": f"Here is the flag encrypted... {ctxt}"})

    def select_e_handler(self, msg):
        e = int(msg["e"])

        if not (2**16 < e < 2**32):
            self.send_message({"res": "Please select an e in the range (2^16, 2^32)"})
            return

        if not GCD(e, self.phiN) == 1:
            self.send_message({"res": "e must be co-prime to phi(N)"})
            return

        self.e = e
        self.d = pow(self.e, -1, self.phiN)
        self.send_message({"res": "RSA public key", "e": self.e, "N": self.N})

    def decrypt_handler(self, msg):
        ctxt = int(msg["ctxt"])

        self.send_message(
            {
                "res": f"Still under construction... throwing your ciphertext ({ctxt}) in the bin"
            }
        )


if __name__ == "__main__":

    class RequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            server = Server(
                flag=FLAG,
                prime_1=PRIME_1,
                prime_2=PRIME_2,
                stdin=self.rfile,
                stdout=self.wfile,
            )
            server.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("0.0.0.0", PORT), RequestHandler).serve_forever()
