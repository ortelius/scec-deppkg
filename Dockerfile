FROM cgr.dev/chainguard/go@sha256:8ed3fdc8f6375a3fd84b4b8b696a2366c3a639931aab492d6f92ca917e726ad6 AS builder

WORKDIR /app
COPY . /app

RUN go install github.com/swaggo/swag/cmd/swag@latest; \
    /root/go/bin/swag init; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:ec603a7b856c4c262d56353505a15b3326ffcedff8e4c890c622745db4ef0a98

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
