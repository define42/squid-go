# syntax=docker/dockerfile:1

FROM golang:alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /squid-go .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /squid-go /squid-go

EXPOSE 443

ENTRYPOINT ["/squid-go"]
