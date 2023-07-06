import subprocess

FILENAME = 'bytecode.bin'

def read_input():
    try:
        h = input(">>> ")
        return bytes.fromhex(h)
    except:
        return b""

def main():
    bytecode = read_input()
    with open(FILENAME, "wb+") as f:
        f.write(bytecode)
    
    out, _ = subprocess.Popen(
        args = ['./vm.bin', FILENAME],
        stdin = subprocess.PIPE,
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE
    ).communicate()
    print(out.decode('utf-8'))

if __name__ == '__main__':
    main()