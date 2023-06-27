import textwrap
import subprocess
import tempfile
import pathlib
import random
import shutil

from Crypto.Util.number import getPrime, bytes_to_long

FLAG = b"CCSC{br0k3n_r4ndomn3zzz_all0ws_for_tr1vial_factoriz4tion}"


def ans1parse_genconf(p: int, q: int, e: int = 0x10001):
    N = p * q
    pubExp = e
    privExp = pow(pubExp, -1, (p - 1) * (q - 1))
    e1 = privExp % (p - 1)
    e2 = privExp % (q - 1)
    coeff = pow(q, -1, p)
    return textwrap.dedent(
        f"""\
            asn1=SEQUENCE:rsa_key

            [rsa_key]
            version=INTEGER:0
            modulus=INTEGER:{N}
            pubExp=INTEGER:{pubExp}
            privExp=INTEGER:{privExp}
            p=INTEGER:{p}
            q=INTEGER:{q}
            e1=INTEGER:{e1}
            e2=INTEGER:{e2}
            coeff=INTEGER:{coeff}"""
    )


if __name__ == "__main__":
    current_dir = pathlib.Path(__file__).parent.resolve()
    public_path = pathlib.Path.joinpath(current_dir, "../public")
    subprocess.check_output(f"rm -f {public_path}/ciphertexts.txt {public_path}/keys.zip", shell=True)

    p = getPrime(1024)
    q1 = getPrime(1024)
    while q1 == p:
        q1 = getPrime(1024)

    q2 = getPrime(1024)
    while q2 in (q1, p):
        q2 = getPrime(1024)

    conf_lst = []
    conf_lst.append((ans1parse_genconf(p, q1), p, q1))
    conf_lst.append((ans1parse_genconf(p, q2), p, q2))
    for i in range(98):
        p = getPrime(1024)
        q = getPrime(1024)
        while q == p:
            q = getPrime(1024)
        conf_lst.append((ans1parse_genconf(p, q), p, q))
        print(f"Parameters for key no. {i+2}")

    random.shuffle(conf_lst)
    ciphertexts_output = ""
    for idx, (conf, p, q) in enumerate(conf_lst):
        with tempfile.NamedTemporaryFile() as tmp_asn:
            tmp_asn.write(conf.encode())
            tmp_asn.flush()
            with tempfile.NamedTemporaryFile() as tmp_der:
                der_output = subprocess.check_output(
                    f"openssl asn1parse -genconf {tmp_asn.name} -out {tmp_der.name}",
                    shell=True,
                )

                with tempfile.NamedTemporaryFile() as tmp_privkey:
                    subprocess.check_output(
                        f"openssl rsa -in {tmp_der.name} -inform der -out {tmp_privkey.name} -text -check",
                        shell=True,
                    )

                    subprocess.check_output(
                        f"openssl rsa -in {tmp_privkey.name} -pubout -out {public_path}/key{idx}.pub",
                        shell=True,
                    )

        ctxt = pow(bytes_to_long(FLAG), 0x10001, p * q)
        ciphertexts_output += f"{idx}:{ctxt}\n"

    shutil.make_archive(f"{public_path}/keys", "zip", f"{public_path}")

    subprocess.check_output(f"rm -f {public_path}/key*.pub", shell=True)
    with open(f"{public_path}/ciphertexts.txt", "w", encoding="utf-8") as f:
        f.write(ciphertexts_output)
