FROM python:3.11
RUN apt-get update
# install common helpful tools
RUN apt-get install -y curl vim jq net-tools htop iptables build-essential iputils-ping iproute2 dnsutils ncat


WORKDIR /vpn
COPY novpn-c ./novpn-c
COPY *.sh ./
COPY *.py ./
RUN cd novpn-c && make
RUN chmod +x *.sh
# docker run --cap-add=NET_ADMIN -i -t vpn /bin/bash