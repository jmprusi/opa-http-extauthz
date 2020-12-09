FROM golang:1.15.1 as builder
COPY . /app/
WORKDIR /app/
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o opa-http-extauthz cmd/opa-http-extauthz/main.go

FROM scratch
COPY --from=builder /app/opa-http-extauthz /tmp/opa-http-extauthz
ENTRYPOINT ["/tmp/opa-http-extauthz"]

