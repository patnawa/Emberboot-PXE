# Build stage
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /emberbootd ./cmd/emberbootd

# Runtime stage — static binary, empty base.
FROM gcr.io/distroless/static-debian12
COPY --from=build /emberbootd /emberbootd
WORKDIR /data
# DHCP/proxyDHCP needs broadcast visibility: run with --network host.
ENTRYPOINT ["/emberbootd", "-config", "/data/emberboot.yaml"]
