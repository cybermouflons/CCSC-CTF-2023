FROM ubuntu:latest

RUN apt-get update && apt-get install -y python3 python3-pip socat && apt-get install nasm

RUN useradd -ms /bin/bash asmr_user
WORKDIR /home/asmr_user

COPY asmr.py .


EXPOSE 6369

CMD ["socat", "TCP-LISTEN:6369,reuseaddr,fork", "EXEC:'python3 asmr.py'"]
