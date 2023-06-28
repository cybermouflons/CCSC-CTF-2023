import builtins
import subprocess



whitelisted_commands = ["print", "len", "range"]

restricted_builtins = {
    "__import__": "Importing modules is not allowed.",
    "eval": "eval() function is not allowed.",
    "exec": "exec() function is not allowed.",
    "open": "File operations are not allowed.",
    "popen": "File operations are not allowed.",
    "locals": "Access to local variables is not allowed.",
    "setattr": "Setting attributes is not allowed.",
    "sys": "sys() function is not allowed.",
     "system": "system function is not allowed.",
     "cat":"cat is not allowed",
     "flag":"flag is not allowed",
}

def restricted():
    while True:
        cmd = input(">> ").lower()
        if any(command in cmd for command in restricted_builtins):
            print("Command not allowed!")
        else:
            try:
                # Execute the command in a restricted environment
                result = None
                namespace = {"__builtins__": builtins}
                exec(compile(cmd, "<string>", "exec"), namespace)
                if result is not None:
                    print(result)
            except Exception as e:
                print("Error:", e)

print("Welcome to my Python jail again, this time will not be that easy :)")
restricted()


