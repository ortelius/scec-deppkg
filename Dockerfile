FROM cgr.dev/chainguard/go@sha256:d09c15520f10a2b44380aa2e1025d3d2bac0864e9f9c4c46c8cd2df9ac48c7e1 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:f8e1f6df91a08766384991641c6ef58e86ca13f205ac8a6127f484c7a23a13fc

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
