FROM alpine:latest

WORKDIR /build/

RUN wget "https://runners-cache-sturdynet.s3.us-west-2.amazonaws.com/rootfs/openwrt-22.03.4-x86-64-generic-rootfs.tar.gz"
RUN tar -xf openwrt-22.03.4-x86-64-generic-rootfs.tar.gz
RUN rm -rf openwrt-22.03.4-x86-64-generic-rootfs.tar.gz

FROM scratch

EXPOSE 80 443 22

ARG WORKDIR=/
ARG USER=root

USER $USER
WORKDIR $WORKDIR

COPY --from=0 --chown=$USER:$USER /build/ ./

CMD ["/sbin/init"]
