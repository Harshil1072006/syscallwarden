FROM golang:1.24-bookworm AS go-build
WORKDIR /build
COPY go.mod .
COPY src/daemon src/daemon
RUN go test -v ./src/daemon && CGO_ENABLED=0 go build -trimpath -o /warden ./src/daemon

FROM debian:bookworm-slim AS native
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm gcc libc6-dev linux-libc-dev libbpf-dev make && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/bpf src/bpf
COPY src/collector src/collector
COPY Makefile .
RUN make native

FROM debian:bookworm-slim AS base
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/warden/lab /run/warden /report && chown -R 65532:65532 /run/warden /report && chmod 0770 /report
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/warden
COPY lab lab

FROM base AS lab
USER 65532:65532
ENTRYPOINT ["python3","/opt/warden/lab/workload.py","serve"]

FROM base AS sensor
RUN apt-get update && apt-get install -y --no-install-recommends libbpf1 && rm -rf /var/lib/apt/lists/*
COPY --from=go-build /warden /opt/warden/warden
COPY --from=native /build/build/collector /build/build/warden.bpf.o /opt/warden/
COPY src/warden src/warden
COPY rules rules
USER 65532:65532
ENTRYPOINT ["/opt/warden/warden"]
CMD ["demo"]
