DIST ?= oe1
PROJECT_TOP_DIR := $(shell git rev-parse --show-toplevel)

all: build

build-image:
	docker build -t qemu-upstream-builder:latest -f Dockerfile.${DIST} .

build: build-image
	docker tag qemu-upstream-builder:latest registry.smtx.io/elf/qemu-upstream-builder:1.0.0
	docker run -v $(PROJECT_TOP_DIR):/home -w /home registry.smtx.io/elf/qemu-upstream-builder:1.0.0 /bin/bash -c /home/binary-build/build.sh
