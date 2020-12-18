FROM ubuntu:groovy

RUN apt update -y
RUN apt-get install -y wget curl

# INSTALL GO AND RUST
RUN wget -c https://golang.org/dl/go1.15.5.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.15.5.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin

# Fetch avalanchego
WORKDIR /root
RUN wget https://github.com/ava-labs/avalanchego/releases/download/v1.1.0/avalanchego-linux-amd64-v1.1.0.tar.gz
RUN tar -xvf avalanchego-linux-amd64-v1.1.0.tar.gz
RUN cp avalanchego-v1.1.0/avalanchego /usr/bin/

# COPY run script
COPY run.sh run.sh
RUN chmod +x run.sh

# RPC SERVER PORT
EXPOSE 9650

# RUN
ENTRYPOINT [ "./run.sh" ]
