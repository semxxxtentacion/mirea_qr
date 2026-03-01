FROM golang:1.23 AS web

WORKDIR /app

COPY go.* ./

RUN go mod download

COPY ../../ .

RUN go build -v -o /app/web ./cmd/web/main.go

EXPOSE 8888

CMD ["/app/web"]