# 只提供一个 Linux 工具链，源码通过 bind mount 进来（见 Makefile），
# 这样在 macOS 上改代码不用重建镜像。
FROM golang:1.27-bookworm

ENV CGO_ENABLED=0 \
    GOFLAGS=-buildvcs=false \
    GOTOOLCHAIN=local

WORKDIR /lab

CMD ["/bin/bash"]
