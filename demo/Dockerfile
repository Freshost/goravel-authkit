FROM golang:1.26-alpine AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=0

WORKDIR /build
COPY . .
WORKDIR /build/demo
RUN go mod download
RUN go build --ldflags "-s -w -extldflags -static" -o main .

FROM alpine:latest

WORKDIR /www

COPY --from=builder /build/demo/main /www/
COPY --from=builder /build/demo/.env /www/.env
COPY --from=builder /build/demo/public/ /www/public/
COPY --from=builder /build/demo/resources/ /www/resources/

ENTRYPOINT ["/www/main"]
