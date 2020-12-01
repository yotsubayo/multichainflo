FROM golang:1.15.5

RUN apt update -y
RUN apt install -y mesa-opencl-icd ocl-icd-opencl-dev gcc git bzr jq pkg-config curl wget hwloc libhwloc-dev
RUN apt upgrade -y

ENV GO111MODULE=on
ENV GOPROXY=https://proxy.golang.org

RUN mkdir -p $(go env GOPATH)
WORKDIR $GOPATH
RUN mkdir -p src/github.com/filecoin-project
WORKDIR $GOPATH/src/github.com/filecoin-project
RUN git clone https://github.com/filecoin-project/filecoin-ffi
WORKDIR $GOPATH/src/github.com/filecoin-project/filecoin-ffi
RUN git checkout 1d9cb3e8ff53f51f
RUN make
RUN go install
