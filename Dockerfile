FROM cgr.dev/chainguard/go@sha256:28343b6ffe88cbfda301d70984a49d4f24bbad56c055e20376524e116bd6e2b4 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:a9cea20608270d361c98cd3304b90baa56a33ff3489a36220c75b18caf22bbe7

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
