FROM python:3.10-slim-bullseye
RUN apt-get update && apt-get install -y socat

WORKDIR /root

RUN python3 -m pip install pwntools==4.10.0

ADD ai_rop.py .
ADD flag.txt .
ENV TERM=linux
ENV TERMINFO=/etc/terminfo

EXPOSE 1337
RUN chmod 755 ./*

CMD ["socat", "-v", "tcp-listen:1337,fork,reuseaddr,su=root", "exec:'python3 -u ai_rop.py'"]
