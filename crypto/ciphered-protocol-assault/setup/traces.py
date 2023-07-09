import numpy as np
from rainbow.generics import rainbow_arm


import lascar
import numpy as np
from lascar.tools.aes import sbox
from rainbow.generics import rainbow_arm
from rainbow import TraceConfig, HammingWeight

e = rainbow_arm(trace_config=TraceConfig(register=HammingWeight()))
e.load("firmware.elf", typ=".elf")
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
    # print(e.trace)
    trace = np.array([event["register"] for event in e.trace]) + np.random.normal(
        0, 1.0, (len(e.trace))
    )
    # trace = e.sca_values_trace + np.random.normal(0, 0.5, (len(e.sca_values_trace)))
    
    return trace

def generate_trace(key):
    plaintext = np.random.randint(0,256,(16,), np.uint8)
    leakage = np.array(encrypt(key, plaintext.tobytes()))
    return leakage, plaintext


N = 200 # number of traces
KEY = b"CCSC{A3S_ScA!1!}"

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

from lascar import Hdf5Container

hdf5 = Hdf5Container.export(acquisition, "tmp.h5")

def selection_function(index, plaintext, key_byte):
    return sbox[plaintext[index] ^ key_byte]

cpa_engines = [
    lascar.CpaEngine("CPA{0}".format(i), selection_function=lambda plaintext, key_byte, index=i: sbox[plaintext[index] ^ key_byte], guess_range=range(256)) for
    i in range(16)
]
s = lascar.Session(AcquisitionSetup(N, KEY), engines=cpa_engines, name="lascar CPA").run()

key = bytes([engine.finalize().max(1).argmax() for engine in cpa_engines])

print("Key is :", key)