FROM golang:1.12.1-alpine3.9 as builder
RUN apk add --no-cache git 
WORKDIR /go/src/github.com/vishen/gcs-secrets
COPY go.mod go.mod
COPY go.sum go.sum
COPY main.go main.go
RUN GO111MODULE=on go mod vendor
RUN CGO_ENABLED=0 go build -tags netgo -installsuffix netgo

FROM alpine:3.9
WORKDIR /app
RUN apk add --no-cache ca-certificates
ADD index.html index.html
ADD secret.html secret.html
ADD css/normalize.css css/normalize.css
ADD css/skeleton.css css/skeleton.css
ADD images/favicon.png images/favicon.png
COPY --from=builder /go/src/github.com/vishen/gcs-secrets/gcs-secrets gcs-secrets
ENTRYPOINT ["/app/gcs-secrets"]
