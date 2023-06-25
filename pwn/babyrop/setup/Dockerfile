FROM ubuntu

# update and install stuff
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y socat gcc-multilib

# add user
RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf

# set workdir and transfer binary
WORKDIR /home/ctf
COPY babyrop .
COPY flag.txt .

RUN chmod 755 ./*

EXPOSE 1337
CMD ["socat", "-v","TCP-LISTEN:1337,reuseaddr,fork,su=ctf", "EXEC:'/home/ctf/babyrop'"]
