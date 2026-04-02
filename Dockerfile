FROM cgr.dev/chainguard/go@sha256:6b3f4f5b1a4dfbcf5fbe707f5b32e7a04154ddae32b3501d06f93c76500f6412 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:62374931e528f0f87cbdf3e24e971f1fa3e7324711da5b11ee5a35cbaa302ec7

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
