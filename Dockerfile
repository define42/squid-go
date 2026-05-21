# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /squid-go .

# Pre-create the cert storage directory with the right ownership/mode so
# the distroless image (which has no shell or mkdir) can use it directly.
RUN mkdir -p /out/var/lib/squid-go && chmod 0700 /out/var/lib/squid-go

FROM gcr.io/distroless/static-debian12:nonroot

# CertMagic needs a writable directory for ACME account keys and issued
# certificates. /var/lib/squid-go is the default value of CERT_STORAGE_PATH;
# override the env var to use a different location.
ENV CERT_STORAGE_PATH=/var/lib/squid-go
WORKDIR /var/lib/squid-go

COPY --from=builder --chown=nonroot:nonroot /out/var/lib/squid-go /var/lib/squid-go
COPY --from=builder /squid-go /squid-go

EXPOSE 443

ENTRYPOINT ["/squid-go"]
