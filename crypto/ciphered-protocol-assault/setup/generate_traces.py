import lascar
import numpy as np
from rainbow import TraceConfig, HammingWeight
from rainbow.generics import rainbow_arm

N = 200  # number of traces
KEY = b"CCSC{A3S_ScA!1!}"

e = rainbow_arm(trace_config=TraceConfig(register=HammingWeight()))
e.load("firmware", typ=".elf")
e.setup()


def encrypt(key: bytes, plaintext: bytes):
    e.reset()

    key_addr = 0xDEAD000
    e[key_addr] = bytes(key)

    # AES128_ECB_indp_setkey(key)
    e["r0"] = key_addr
    e.start(e.functions["AES128_ECB_indp_setkey"] | 1, 0)

    buffer_in = 0xDEAD1000
    e[buffer_in] = plaintext
    # AES128_ECB_indp_crypto(input)
    e["r0"] = buffer_in
    e["lr"] = 0

    e.reset_trace()
    e.start(e.functions["AES128_ECB_indp_crypto"] | 1, 0)

    # add some random noise
    trace = np.array([event["register"] for event in e.trace]) + np.random.normal(
        0, 1.0, (len(e.trace))
    )

    return trace


class AcquisitionSetup(lascar.AbstractContainer):
    def __init__(self, number_of_traces: int, key: bytes):
        self.key = key
        super().__init__(number_of_traces)

    def generate_trace(self, idx):
        print("Generate trace %d" % idx)
        plaintext = np.random.randint(0, 256, (16,), np.uint8)
        leakage = encrypt(self.key, plaintext.tobytes())
        return lascar.Trace(leakage, plaintext)


acquisition = AcquisitionSetup(N, KEY)

hdf5 = lascar.Hdf5Container.export(acquisition, "traces.h5")
