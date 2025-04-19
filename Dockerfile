FROM cgr.dev/chainguard/go@sha256:dc696d01258a1a8c0434e14fc218437ce94d3277adc02c63e9e80d628d5af7e9 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:c8c17d42716bfaa23ce92570baa3fc1573c73c0d54df487608a6ebdf2ce8b2be

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/docs docs

ENV ARANGO_HOST localhost
ENV ARANGO_USER root
ENV ARANGO_PASS rootpassword
ENV ARANGO_PORT 8529
ENV MS_PORT 8080

EXPOSE 8080

ENTRYPOINT [ "/app/main" ]
