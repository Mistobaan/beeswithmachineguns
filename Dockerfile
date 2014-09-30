FROM golang:1.3.1

RUN go get github.com/tsenart/vegeta
RUN go install github.com/tsenart/vegeta

ENTRYPOINT /go/bin/vegeta
