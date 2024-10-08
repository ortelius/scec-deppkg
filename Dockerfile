FROM cgr.dev/chainguard/go@sha256:2dbbaf104d1e38c4f456ccc5684fcd04e589393b2ab0e1def7d373eec1439751 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:cabf47ee4e6e339b32a82cb84b6779e128bb9e1f2441b0d8883ffbf1f8b54dd2

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
