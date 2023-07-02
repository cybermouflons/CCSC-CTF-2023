FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
        apt-get -y upgrade && \
        apt-get install -y apt-utils && \
        apt-get install -y xinetd iproute2 socat
RUN apt-get install -y qemu-system-x86

RUN groupadd -r user && useradd -r -g user user

COPY --chown=root:user ./run.sh /
COPY --chown=root:user ./initramfs.cpio.gz /
COPY --chown=root:user ./bzImage /

RUN chmod 555 ./run.sh && \
    chmod 444 /etc/xinetd.d/pwn

#USER user
EXPOSE 1337

#CMD ["xinetd","-d","-dontfork","-f","/etc/xinetd.d/pwn"]
CMD ["socat", "-v","TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'/run.sh'"]