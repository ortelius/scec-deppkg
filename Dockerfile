FROM cgr.dev/chainguard/go@sha256:a2ed1fb84ada1a2bbc5739501c37f49d8f488877f67a944dcf1c79d55d6e4d95 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:e24942d03338c8e3f717ca27f0b112edc12e92e6f30e4fd3a8807dd5bcde566d

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
