# First image used to build the sources
FROM golang:1.25.3 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY . .

# ENV GOPROXY=https://goproxy.io,direct
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o ./bin/introspector ./cmd/introspector.go

# Second image, running the executable
FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/* /app/

ENV PATH="/app:${PATH}"
ENV INTROSPECTOR_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT [ "introspector" ]
