FROM golang:1.10 AS bldr

WORKDIR /go/src/github.com/tanner-bruce/execer

COPY main.go ./
COPY cmd cmd/
COPY vendor vendor/

RUN GOOS=linux CGO_ENABLED=false go build main.go && cp main /execer

FROM scratch
COPY --from=bldr /execer /execer
ENTRYPOINT ["/execer"]
