FROM ubuntu:latest

RUN apt-get update && apt-get install -y python3 python3-pip socat

RUN useradd -ms /bin/bash jail_user
WORKDIR /home/jail_user

COPY jail.py .
COPY /flag/flag.txt /flag/flag.txt


EXPOSE 4689

CMD ["socat", "TCP-LISTEN:4689,reuseaddr,fork", "EXEC:'python3 jail.py'"]
