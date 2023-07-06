FROM ubuntu:lunar

RUN apt-get update && apt-get install -y socat make g++-13 python3

RUN useradd -ms /bin/bash user
WORKDIR /home/user/app

COPY include/ include/
COPY src/ src/
COPY Makefile .

COPY flag.txt ../
COPY wrapper.py .

RUN make

RUN rm -rf src
RUN rm -rf include

EXPOSE 6666

CMD ["socat", "TCP-LISTEN:6666,reuseaddr,fork", "EXEC:'python3 ./wrapper.py'"]