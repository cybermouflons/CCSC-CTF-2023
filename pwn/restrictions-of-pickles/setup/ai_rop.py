#!/usr/bin/env python3

import pickle
from pickletools import genops
import io
import pwnlib
from pwn import ELF


def super_exploit(name):
    print(f"Hello {name}! Here's what you need to run to hack Python: ")
    return "os.system('/bin/bash')"


def bad_hacker():
    print("Sorry, the AI is a much better hacker than you")


binary = ELF("/bin/mv")
pwnlib.rop.rop.__dict__["super_exploit"] = super_exploit
pwnlib.rop.rop.__dict__["bad_hacker"] = bad_hacker

ADVANCED_AI_ROP = pwnlib.rop.rop.ROP(binary)
ADVANCED_AI_ROP(rdi=0xDEADBEEF, rsi=0xCAFEBABE)


class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        print("Only ROP stuff here!")

        if "__" in name:
            raise pickle.UnpicklingError("Error")

        if module == "pwnlib.rop" and name in dir(pwnlib.rop):
            return getattr(pwnlib.rop, name)
        if module == "pwnlib.rop.rop" and name in dir(pwnlib.rop.rop):
            return getattr(pwnlib.rop.rop, name)
        if module == "pwnlib.rop.rop.ROP" and name in dir(pwnlib.rop.rop.ROP):
            return getattr(pwnlib.rop.rop.ROP, name)

        raise pickle.UnpicklingError("Error")


def menu():
    print("Welcome to the AI Exploit Playground!")
    print(
        "I've become the best at creating exploits from training on the CYberMouflons CTF solutions!"
    )
    print("===================================")
    print("1. Submit your own pickled ROP class")
    print("2. Check if you can create a better ROP chain than me")
    print("3. Test your ROP chain")
    print("===================================")


def submit_payload():
    data = bytes.fromhex(input("Provide your pickled ROP class (hex): "))

    for op in genops(data):
        if op[0].name == "REDUCE":
            print("Don't try to get cheeky there...")
            exit(-1)

    user_rop = SafeUnpickler(io.BytesIO(data)).load()

    return user_rop


def compare_hacking(USER_ROP):
    ai_chain = ADVANCED_AI_ROP.chain()

    if USER_ROP is None:
        print("You have to submit your ROP class first!")
        return

    user_chain = USER_ROP(binary).chain()

    if user_chain != ai_chain:
        print("Alright, I guess you are a pretty good hacker")
        name = input("What's your name? ")
        print(pwnlib.rop.rop.super_exploit(name))
    else:
        print("You for sure asked GPT-12456")
        print(pwnlib.rop.rop.bad_hacker())


def check_rop_chain(USER_ROP):
    print("Here is your ROP chain:")

    my_rop = USER_ROP(binary)
    print(my_rop.chain())


def main():
    menu()
    payload_submitted = False

    user_rop = None
    while True:
        choice = input("Enter your choice (1-3): ").strip()

        if choice == "1":
            if not payload_submitted:
                payload_submitted = True
                user_rop = submit_payload()
                if user_rop != pwnlib.rop.rop.ROP:
                    print("You need to submit a ROP class!")
                    exit(-1)
            else:
                print("You have already submitted your payload!")
        elif choice == "2":
            compare_hacking(user_rop)
        elif choice == "3":
            check_rop_chain(user_rop)
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
