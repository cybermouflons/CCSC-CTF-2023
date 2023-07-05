FROM python:3.10-slim-bookworm

RUN apt-get update && apt-get install -y socat

RUN useradd -ms /bin/bash jail_user
WORKDIR /home/jail_user

COPY disbelief.py .
COPY flag.txt /flag/flag.txt

EXPOSE 4689

CMD ["socat", "TCP-LISTEN:4690,reuseaddr,fork", "EXEC:'python3 disbelief.py'"]
