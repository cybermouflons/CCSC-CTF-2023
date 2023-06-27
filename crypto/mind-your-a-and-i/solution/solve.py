import shutil
import pathlib
import subprocess
import itertools

from typing import List, Tuple

from Crypto.PublicKey import RSA
from Crypto.Util.number import GCD, long_to_bytes

if __name__ == "__main__":
    current_dir = pathlib.Path(__file__).parent.resolve()
    public_path = pathlib.Path.joinpath(current_dir, "../public")
    shutil.unpack_archive(f"{public_path}/keys.zip", f"{current_dir}", "zip")

    rsa_keys: List[Tuple[RSA.RsaKey, int]] = []
    for i in range(100):
        with open(f"{current_dir}/key{i}.pub", "r", encoding="utf-8") as f:
            key = RSA.import_key(f.read())
            rsa_keys.append((key, i))

    subprocess.check_output(
        f"rm -f {current_dir}/key*.pub", shell=True
    )

    for element1, element2 in itertools.product(rsa_keys, repeat=2):
        rsa1, idx1 = element1
        rsa2, idx2 = element2

        if GCD(rsa1.n, rsa2.n) not in [1, rsa1.n]:
            p = GCD(rsa1.n, rsa2.n)
            q = rsa1.n // p
            phiN = (p - 1) * (q - 1)
            e = rsa1.e
            d = pow(e, -1, phiN)

            with open(f"{public_path}/ciphertexts.txt", "r", encoding="utf-8") as f:
                ciphertexts = f.readlines()
                ctxt = int(ciphertexts[idx1].split(":")[-1])
                flag_int = pow(ctxt, d, p * q)
                print(long_to_bytes(flag_int))

            break
