FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    locales socat

# Set the locale
RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf

WORKDIR /home/ctf

ADD chopper .
ADD flag.txt .

RUN chmod 755 ./*

EXPOSE 1337
CMD ["socat", "-v", "TCP-LISTEN:1337,reuseaddr,fork,su=root", "EXEC:/home/ctf/chopper"]
