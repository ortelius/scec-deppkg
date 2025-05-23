FROM cgr.dev/chainguard/go@sha256:0d82b93b1d3eb16334eee43500aa337daa82ab8a81da053a95516d3c17d50e31 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:1085eb515b8fe84b5803d2223d73963411a89fda7de52378365bacbc42ca5ba6

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
