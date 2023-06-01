FROM scratch

ADD ./ /

EXPOSE 80 443 22

ARG USER=root

USER $USER
CMD ["/sbin/init"]
