FROM cgr.dev/chainguard/go@sha256:012ee715777a66368dd8d7b02a2d51a6fff72aa4dfa71ac06ca650bbc4da317b AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:9a661991ed70262504d6618944c70d85f76a2dcff633ad7b4b2d9a2ee235b3c0

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
