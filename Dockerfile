FROM cgr.dev/chainguard/go@sha256:2bf52f03dea2140fdb42169af8fe5e99ac868807cdf96628c91c8c1b20ee96ef AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:ef35f036cfe4d7ee20107ab358e038da0be69e93304c8c62dc8e5c0787d9a9c5

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
