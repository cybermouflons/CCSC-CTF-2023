# pip install "git+https://github.com/Ledger-Donjon/lascar.git"

import h5py

from lascar import TraceBatchContainer, Session, CpaEngine
from lascar.tools.aes import sbox

with h5py.File("traces.h5", "r") as f:
    leakages = f["leakages"][:]
    plaintexts = f["values"][:]

container = TraceBatchContainer(leakages, plaintexts)

cpa_engines = [
    CpaEngine(
        "CPA{0}".format(i),
        selection_function=lambda plaintext, key_byte, index=i: sbox[
            plaintext[index] ^ key_byte
        ],
        guess_range=range(256),
    )
    for i in range(16)
]
s = Session(container, engines=cpa_engines, name="lascar CPA").run()

key = bytes([engine.finalize().max(1).argmax() for engine in cpa_engines])

print("Key is :", key)
