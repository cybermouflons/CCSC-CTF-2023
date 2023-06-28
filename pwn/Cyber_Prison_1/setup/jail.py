import builtins
import subprocess

class flag:
    @staticmethod
    def read_flag():
        flag_path = '/flag/flag.txt'
        with open(flag_path, 'r') as file:
            flag = file.read().strip()
        return flag

builtins.flag = flag

whitelisted_commands = ["print", "len", "range"]

restricted_builtins = {
    "__import__": "Importing modules is not allowed.",
    "eval": "eval() function is not allowed.",
    "exec": "exec() function is not allowed.",
    "open": "File operations are not allowed.",
    "popen": "File operations are not allowed.",
    "globals": "Access to global variables is not allowed.",
    "locals": "Access to local variables is not allowed.",
    "setattr": "Setting attributes is not allowed.",
    "getattr": "Getting attributes is not allowed.",
    "sys": "sys() function is not allowed.",
    "flag.txt": "NICE TRY;p.",
}

def restricted():
    while True:
        cmd = input(">> ").lower().strip()
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

print("Welcome to my Python jail, no one managed to escape so far...i think ;-)")
restricted()


