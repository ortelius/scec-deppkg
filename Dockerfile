FROM cgr.dev/chainguard/go@sha256:16011144354e0e722d7286d255c670dfd72f1023b93491faab0d8e67919966ed AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:c7edeee3667ccd98e46de1e20bdd1b73df84f34a9da83b3723760000ae4de401

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
