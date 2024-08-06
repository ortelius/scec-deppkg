FROM cgr.dev/chainguard/go@sha256:3c127f004628d86809759f5172a780f3c00bb8ab7fc4d7f13f546bc3dfeafadc AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:b7eac07361485e71cd0908a6a913f8b2006cf04fef6137f2c9291be00a67ebcc

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
