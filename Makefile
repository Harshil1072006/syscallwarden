PYTHON ?= python3
CC ?= cc
CLANG ?= clang
MULTIARCH := $(shell $(CC) -dumpmachine)
export PYTHONDONTWRITEBYTECODE=1

.PHONY: test daemon-test native demo live bench
test:
	$(PYTHON) -m unittest discover -s tests -v

daemon-test:
	go test -v ./src/daemon

native: build/warden.bpf.o build/collector

build/warden.bpf.o: src/bpf/warden.bpf.c src/bpf/wire.h
	mkdir -p build
	$(CLANG) -O2 -g -target bpfel -mcpu=v3 -I/usr/include/$(MULTIARCH) -c $< -o $@

build/collector: src/collector/collector.c src/collector/encode.c src/collector/encode.h src/bpf/wire.h
	mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror src/collector/collector.c src/collector/encode.c -lbpf -o $@

demo:
	sh lab/compose-run.sh demo

live:
	sh lab/compose-run.sh live

bench:
	$(PYTHON) tests/benchmark.py
