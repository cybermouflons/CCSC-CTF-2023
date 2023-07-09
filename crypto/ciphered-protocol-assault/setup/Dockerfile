FROM stronglytyped/arm-none-eabi-gcc:latest as builder

COPY . /workspace

WORKDIR /workspace

RUN make all 

FROM python:3.10-bookworm 

WORKDIR /workspace

COPY --from=builder /workspace/firmware ./

RUN git clone https://github.com/Ledger-Donjon/rainbow.git

COPY rainbow.patch ./rainbow/

RUN cd rainbow && \
    git checkout 3c2426ddd1524b83ce2c28b441c9eae950eb9fe9 && \
    git apply rainbow.patch 

RUN cd rainbow && \
    pip install . && \
    pip3 install "git+https://github.com/Ledger-Donjon/lascar.git"


COPY generate_traces.py .

RUN python generate_traces.py
