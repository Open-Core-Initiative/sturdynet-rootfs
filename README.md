# Containerized Studynet

## Simple Example

```
docker run --rm -it sturdynetoci/rootfs:latest
# inside the Docker container
opkg update
opkg install tmate
tmate

```

Enjoy a local Sturdynet container running the x86/64 architecture with internet access. Once closed the container is removed.

## Expose Ports

```
sudo docker run --rm -it -p 7433:80 -p 8443:443 -p 8822:22 sturdynetoci/rootfs:latest
# inside the Docker container
opkg update
opkg install tmate
tmate

```
