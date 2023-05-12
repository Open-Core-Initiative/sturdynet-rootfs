# FROM alpine:latest

# WORKDIR /build/

# RUN wget "https://runners-cache-sturdynet.s3.us-west-2.amazonaws.com/rootfs/openwrt-22.03.4-x86-64-generic-rootfs.tar.gz"
# RUN tar xf openwrt-22.03.4-x86-64-generic-rootfs.tar.gz --strip=1 --no-same-owner -C .
# RUN rm -rf openwrt-22.03.4-x86-64-generic-rootfs.tar.gz

FROM scratch

ADD ./ /

EXPOSE 80 443 22

ARG USER=root
# ARG WORKDIR=/
# ARG CMD=ash


USER $USER
# WORKDIR $WORKDIR

# COPY --from=0 --chown=$USER:$USER /build/ ./

# ENV CMD_ENV=${CMD}
# CMD ${CMD_ENV}
CMD ["/sbin/init"]
