IMAGE  := seccomp-lab
PWDIR  := $(shell pwd)

# 说明：
#   --security-opt seccomp=unconfined  Docker 自己默认就挂了一层 seccomp 过滤器，
#                                      我们要在容器里再装过滤器，直接放开避免互相干扰。
#   --cap-add SYS_PTRACE                supervisor 要读 /proc/<tid>/mem，需要 ptrace 权限。
RUN := docker run --rm -v "$(PWDIR)":/lab -w /lab \
	--security-opt seccomp=unconfined --cap-add SYS_PTRACE $(IMAGE)

.PHONY: image build check shell demo1 demo2 demo3 demo4 demo5 all clean

image:
	docker build -t $(IMAGE) .

build:
	$(RUN) go build -o bin/ ./cmd/...

# 不需要 Docker：在宿主机上按 linux 交叉编译 + vet，最快的一遍验证。
check:
	GOOS=linux GOARCH=amd64 go build -o /tmp/seccomp-check/ ./...
	GOOS=linux GOARCH=amd64 go vet ./...

shell: image
	docker run --rm -it -v "$(PWDIR)":/lab -w /lab \
		--security-opt seccomp=unconfined --cap-add SYS_PTRACE $(IMAGE) bash

demo1: build
	$(RUN) ./bin/01-basic

demo2: build
	$(RUN) ./bin/02-notify

demo3: build
	$(RUN) ./scripts/demo3.sh

demo4: build
	$(RUN) ./bin/04-race

demo5: build
	$(RUN) ./bin/05-fail-open

all: image demo1 demo2 demo3 demo4 demo5

clean:
	rm -rf bin
