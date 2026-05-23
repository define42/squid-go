# syntax=docker/dockerfile:1

FROM golang:1.26-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS builder

# CA certificates are required at runtime: CertMagic/ACME makes outbound HTTPS
# calls to Let's Encrypt, and scratch ships no trust store. Install them here
# so they can be copied into the final image.
RUN apk add --no-cache ca-certificates

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /squid-go .

# scratch has no shell, mkdir, or user database, so stage everything the final
# image needs:
#   - the cert storage directory (default CERT_STORAGE_PATH); ownership/mode are
#     applied by the COPY --chown/--chmod below so the unprivileged user can
#     write the ACME keys/certs CertMagic stores there.
#   - passwd/group entries so the container can run as a non-root user.
# UID/GID 65532 matches the "nonroot" user used by distroless images.
RUN mkdir -p /out/etc /out/var/lib/squid-go \
    && echo 'nonroot:x:65532:65532:nonroot:/var/lib/squid-go:/sbin/nologin' > /out/etc/passwd \
    && echo 'nonroot:x:65532:' > /out/etc/group

FROM scratch

# CertMagic needs a writable directory for ACME account keys and issued
# certificates. /var/lib/squid-go is the default value of CERT_STORAGE_PATH;
# override the env var to use a different location.
ENV CERT_STORAGE_PATH=/var/lib/squid-go

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/etc/passwd /etc/passwd
COPY --from=builder /out/etc/group /etc/group
# Let COPY create the directory so --chown/--chmod apply to it. Setting WORKDIR
# first would pre-create it as root and the ownership would never be applied,
# breaking writes when a named volume inherits that ownership.
COPY --from=builder --chown=65532:65532 --chmod=0700 /out/var/lib/squid-go /var/lib/squid-go
COPY --from=builder /squid-go /squid-go

WORKDIR /var/lib/squid-go
USER 65532:65532

EXPOSE 443

ENTRYPOINT ["/squid-go"]
