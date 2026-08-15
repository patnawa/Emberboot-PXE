# Build stage. Keep this version aligned with go.mod's security patch floor.
FROM golang:1.25.13 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/emberbootd ./cmd/emberbootd
COPY internal ./internal
# Production/release builds must pass the immutable release identifier, for
# example: docker build --build-arg VERSION=v0.6.0 -f deploy/Dockerfile .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /emberbootd ./cmd/emberbootd \
    && mkdir -p /runtime-data \
    && chmod 0700 /runtime-data

# Runtime stage: static binary, no shell/package manager, unprivileged UID.
FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="Emberboot" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build --chown=65532:65532 /emberbootd /emberbootd
COPY --from=build --chown=65532:65532 /runtime-data /data
WORKDIR /data
# The mounted /data volume must be writable by UID/GID 65532. DHCP/proxyDHCP
# also needs host networking and only NET_BIND_SERVICE + NET_RAW capabilities.
USER 65532:65532
VOLUME ["/data"]
ENTRYPOINT ["/emberbootd", "-config", "/data/emberboot.yaml"]
