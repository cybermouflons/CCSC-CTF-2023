import opcode
import types


restricted = {
    opcode.opmap[k]
    for k in opcode.opmap
    if ("LOAD" in k and k != "LOAD_CONST")
    or ("CALL" in k and k != "CALL_FUNCTION")
    or "IMPORT" in k
    or "MAKE" in k
}

h = input(">>> ")
code = bytes.fromhex(h)

if len(code) % 2 != 0:
    print("This does not look right....")
    exit(1)

if any(code[i] in restricted for i in range(0, len(code), 2)):
    print("Your efforts are futile, you pitiful human....")
    exit(1)

code_obj = types.CodeType(
    0,
    0,
    0,
    0,
    64,
    64,
    code,
    (1, chr, getattr),
    (),
    (),
    "disbelief",
    "<module>",
    1,
    b"",
    (),
    (),
)

print(eval(code_obj, {"__builtins__": {}}, {}))
